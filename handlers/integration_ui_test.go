package handlers

import (
	"gatekeeper/database"
	"gatekeeper/models"
	"testing"
	"time"
)

// TestExecutionFailedIntegration tests the complete execution_failed workflow
func TestExecutionFailedIntegration(t *testing.T) {
	setupTestDatabase()
	
	// Create test users
	applicantID, err := createTestUser("12345", "applicant")
	if err != nil {
		t.Fatal(err)
	}
	
	approverID, err := createTestUser("admin2", "approver")
	if err != nil {
		t.Fatal(err)
	}
	
	// Step 1: Create a pending application
	appID, err := createTestApplication(applicantID, "192.168.1.100", 8080, "pending")
	if err != nil {
		t.Fatal(err)
	}
	
	t.Logf("Step 1: Created pending application ID=%d", appID)
	
	// Step 2: Simulate approval failure (iptables error)
	// This would normally happen in ApproveHandler when iptables fails
	now := time.Now()
	_, err = database.DB.Exec("UPDATE applications SET status = ?, updated_at = ? WHERE id = ?", 
		"execution_failed", now, appID)
	if err != nil {
		t.Fatal(err)
	}
	
	t.Logf("Step 2: Simulated iptables failure - status changed to execution_failed")
	
	// Step 3: Verify application appears in approver's pending list (NEW behavior)
	pendingApps := getApproverPendingApplications(t)
	
	found := false
	var foundApp models.Application
	for _, app := range pendingApps {
		if app.ID == int(appID) {
			found = true
			foundApp = app
			break
		}
	}
	
	if !found {
		t.Error("execution_failed application should be visible to approvers")
	} else {
		if foundApp.Status != "execution_failed" {
			t.Errorf("Expected status 'execution_failed', got '%s'", foundApp.Status)
		}
		t.Logf("Step 3: ✅ execution_failed application visible to approvers")
	}
	
	// Step 4: Verify application appears in user's "my applications"
	myApps := getUserApplications(t, applicantID)
	
	foundInMyApps := false
	for _, app := range myApps {
		if app.ID == int(appID) && app.Status == "execution_failed" {
			foundInMyApps = true
			break
		}
	}
	
	if !foundInMyApps {
		t.Error("execution_failed application should be visible in user's applications")
	} else {
		t.Logf("Step 4: ✅ execution_failed application visible to user")
	}
	
	// Step 5: Simulate successful retry
	_, err = database.DB.Exec("UPDATE applications SET status = ?, updated_at = ? WHERE id = ?", 
		"approved", time.Now(), appID)
	if err != nil {
		t.Fatal(err)
	}
	
	t.Logf("Step 5: Simulated successful retry - status changed to approved")
	
	// Step 6: Verify application no longer appears in approver's pending list
	pendingAppsAfterRetry := getApproverPendingApplications(t)
	
	stillPending := false
	for _, app := range pendingAppsAfterRetry {
		if app.ID == int(appID) {
			stillPending = true
			break
		}
	}
	
	if stillPending {
		t.Error("approved application should not appear in pending list")
	} else {
		t.Logf("Step 6: ✅ approved application removed from pending list")
	}
	
	// Step 7: Verify application shows as approved in user's applications
	myAppsAfterRetry := getUserApplications(t, applicantID)
	
	approvedFound := false
	for _, app := range myAppsAfterRetry {
		if app.ID == int(appID) && app.Status == "approved" {
			approvedFound = true
			break
		}
	}
	
	if !approvedFound {
		t.Error("application should show as approved in user's applications")
	} else {
		t.Logf("Step 7: ✅ application shows as approved in user's applications")
	}
	
	t.Logf("Integration test completed successfully - users: applicant=%d, approver=%d", 
		applicantID, approverID)
}

// TestDashboardDataIntegrity tests that dashboard queries return correct data structure
func TestDashboardDataIntegrity(t *testing.T) {
	setupTestDatabase()
	
	// Create test user
	applicantID, err := createTestUser("12345", "applicant")
	if err != nil {
		t.Fatal(err)
	}
	
	// Create applications with all possible statuses
	statuses := []string{"pending", "execution_failed", "approved", "rejected", "removed"}
	appIDs := make(map[string]int64)
	
	for i, status := range statuses {
		appID, err := createTestApplication(applicantID, "192.168.1."+string(rune(100+i)), 8080+i, status)
		if err != nil {
			t.Fatal(err)
		}
		appIDs[status] = appID
	}
	
	// Test approver pending applications query
	pendingApps := getApproverPendingApplications(t)
	
	// Should include pending and execution_failed
	expectedInPending := []string{"pending", "execution_failed"}
	foundStatuses := make(map[string]bool)
	
	for _, app := range pendingApps {
		// Verify all required fields are present and non-empty
		if app.ID == 0 {
			t.Error("Application ID should not be zero")
		}
		if app.IPAddress == "" {
			t.Error("IP address should not be empty")
		}
		if app.Port == 0 {
			t.Error("Port should not be zero")
		}
		if app.Reason == "" {
			t.Error("Reason should not be empty")
		}
		if app.Status == "" {
			t.Error("Status should not be empty")
		}
		if app.Username == "" {
			t.Error("Username should not be empty")
		}
		if app.CreatedAt.IsZero() {
			t.Error("CreatedAt should not be zero")
		}
		
		foundStatuses[app.Status] = true
	}
	
	for _, expectedStatus := range expectedInPending {
		if !foundStatuses[expectedStatus] {
			t.Errorf("Expected status '%s' not found in pending applications", expectedStatus)
		}
	}
	
	// Should NOT include approved, rejected, removed
	unexpectedStatuses := []string{"approved", "rejected", "removed"}
	for _, unexpectedStatus := range unexpectedStatuses {
		if foundStatuses[unexpectedStatus] {
			t.Errorf("Unexpected status '%s' found in pending applications", unexpectedStatus)
		}
	}
	
	// Test user applications query
	myApps := getUserApplications(t, applicantID)
	
	// Should include ALL statuses
	allStatusesFound := make(map[string]bool)
	for _, app := range myApps {
		// Verify all required fields are present
		if app.ID == 0 {
			t.Error("Application ID should not be zero")
		}
		if app.IPAddress == "" {
			t.Error("IP address should not be empty")
		}
		if app.Port == 0 {
			t.Error("Port should not be zero")
		}
		if app.Reason == "" {
			t.Error("Reason should not be empty")
		}
		if app.Status == "" {
			t.Error("Status should not be empty")
		}
		if app.CreatedAt.IsZero() {
			t.Error("CreatedAt should not be zero")
		}
		
		allStatusesFound[app.Status] = true
	}
	
	// Verify all statuses are present in user's applications
	for _, status := range statuses {
		if !allStatusesFound[status] {
			t.Errorf("Expected status '%s' not found in user applications", status)
		}
	}
	
	t.Logf("Data integrity test completed - pending apps: %d, my apps: %d", 
		len(pendingApps), len(myApps))
	t.Logf("Created applications: %v", appIDs)
}

// TestStatusTransitionWorkflow tests the complete status transition workflow
func TestStatusTransitionWorkflow(t *testing.T) {
	setupTestDatabase()
	
	// Create test user
	applicantID, err := createTestUser("12345", "applicant")
	if err != nil {
		t.Fatal(err)
	}
	
	// Test case 1: Normal approval workflow
	t.Run("Normal Approval", func(t *testing.T) {
		appID, err := createTestApplication(applicantID, "192.168.1.100", 8080, "pending")
		if err != nil {
			t.Fatal(err)
		}
		
		// pending -> approved
		updateApplicationStatus(int(appID), "approved", "")
		verifyApplicationStatus(t, appID, "approved")
		
		// approved -> removed
		updateApplicationStatus(int(appID), "removed", "")
		verifyApplicationStatus(t, appID, "removed")
	})
	
	// Test case 2: Rejection workflow
	t.Run("Rejection", func(t *testing.T) {
		appID, err := createTestApplication(applicantID, "192.168.1.101", 8081, "pending")
		if err != nil {
			t.Fatal(err)
		}
		
		// pending -> rejected
		updateApplicationStatus(int(appID), "rejected", "Security policy violation")
		verifyApplicationStatus(t, appID, "rejected")
		
		// Verify rejection reason
		var rejectionReason string
		err = database.DB.QueryRow("SELECT rejection_reason FROM applications WHERE id = ?", appID).
			Scan(&rejectionReason)
		if err != nil {
			t.Fatal(err)
		}
		
		if rejectionReason != "Security policy violation" {
			t.Errorf("Expected rejection reason 'Security policy violation', got '%s'", rejectionReason)
		}
	})
	
	// Test case 3: Execution failure and retry workflow
	t.Run("Execution Failure and Retry", func(t *testing.T) {
		appID, err := createTestApplication(applicantID, "192.168.1.102", 8082, "pending")
		if err != nil {
			t.Fatal(err)
		}
		
		// pending -> execution_failed
		updateApplicationStatus(int(appID), "execution_failed", "")
		verifyApplicationStatus(t, appID, "execution_failed")
		
		// Verify it appears in pending list
		pendingApps := getApproverPendingApplications(t)
		found := false
		for _, app := range pendingApps {
			if app.ID == int(appID) && app.Status == "execution_failed" {
				found = true
				break
			}
		}
		if !found {
			t.Error("execution_failed application should appear in pending list")
		}
		
		// execution_failed -> approved (retry success)
		updateApplicationStatus(int(appID), "approved", "")
		verifyApplicationStatus(t, appID, "approved")
		
		// Verify it no longer appears in pending list
		pendingAppsAfter := getApproverPendingApplications(t)
		stillFound := false
		for _, app := range pendingAppsAfter {
			if app.ID == int(appID) {
				stillFound = true
				break
			}
		}
		if stillFound {
			t.Error("approved application should not appear in pending list")
		}
	})
	
	// Test case 4: Execution failure and manual rejection
	t.Run("Execution Failure and Manual Rejection", func(t *testing.T) {
		appID, err := createTestApplication(applicantID, "192.168.1.103", 8083, "pending")
		if err != nil {
			t.Fatal(err)
		}
		
		// pending -> execution_failed
		updateApplicationStatus(int(appID), "execution_failed", "")
		verifyApplicationStatus(t, appID, "execution_failed")
		
		// execution_failed -> rejected (manual rejection after failure)
		updateApplicationStatus(int(appID), "rejected", "Manual rejection after execution failure")
		verifyApplicationStatus(t, appID, "rejected")
		
		// Verify rejection reason
		var rejectionReason string
		err = database.DB.QueryRow("SELECT rejection_reason FROM applications WHERE id = ?", appID).
			Scan(&rejectionReason)
		if err != nil {
			t.Fatal(err)
		}
		
		expected := "Manual rejection after execution failure"
		if rejectionReason != expected {
			t.Errorf("Expected rejection reason '%s', got '%s'", expected, rejectionReason)
		}
	})
}

// Helper functions

func getApproverPendingApplications(t *testing.T) []models.Application {
	rows, err := database.DB.Query(`
		SELECT a.id, a.ip_address, a.port, a.reason, a.status, a.expires_at, a.created_at, u.username
		FROM applications a JOIN users u ON a.user_id = u.id
		WHERE a.status IN ('pending', 'execution_failed') ORDER BY a.created_at DESC`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	
	var applications []models.Application
	for rows.Next() {
		var app models.Application
		err := rows.Scan(&app.ID, &app.IPAddress, &app.Port, &app.Reason, &app.Status, &app.ExpiresAt, &app.CreatedAt, &app.Username)
		if err != nil {
			t.Fatal(err)
		}
		applications = append(applications, app)
	}
	
	return applications
}

func getUserApplications(t *testing.T, userID int64) []models.Application {
	rows, err := database.DB.Query(`
		SELECT id, ip_address, port, reason, status, expires_at, created_at
		FROM applications WHERE user_id = ? ORDER BY created_at DESC`, userID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	
	var applications []models.Application
	for rows.Next() {
		var app models.Application
		err := rows.Scan(&app.ID, &app.IPAddress, &app.Port, &app.Reason, &app.Status, &app.ExpiresAt, &app.CreatedAt)
		if err != nil {
			t.Fatal(err)
		}
		applications = append(applications, app)
	}
	
	return applications
}

func verifyApplicationStatus(t *testing.T, appID int64, expectedStatus string) {
	var actualStatus string
	err := database.DB.QueryRow("SELECT status FROM applications WHERE id = ?", appID).Scan(&actualStatus)
	if err != nil {
		t.Fatal(err)
	}
	
	if actualStatus != expectedStatus {
		t.Errorf("Expected status '%s', got '%s' for application %d", expectedStatus, actualStatus, appID)
	}
}