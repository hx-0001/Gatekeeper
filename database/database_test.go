package database

import (
	"database/sql"
	"gatekeeper/models"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "github.com/mattn/go-sqlite3"
)

func TestMain(m *testing.M) {
	// Setup test database
	testDB := ":memory:"
	InitDB(testDB)
	
	// Run tests
	code := m.Run()
	
	// Cleanup
	if DB != nil {
		DB.Close()
	}
	
	os.Exit(code)
}

func setupTestDB() {
	// Clear existing data
	DB.Exec("DELETE FROM applications")
	DB.Exec("DELETE FROM users WHERE username != 'admin'")
}

func TestInitDB(t *testing.T) {
	if DB == nil {
		t.Error("Database should be initialized")
	}
	
	// Test that tables exist
	var count int
	err := DB.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('users', 'applications')").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query tables: %v", err)
	}
	
	if count != 2 {
		t.Errorf("Expected 2 tables (users, applications), got %d", count)
	}
}

func TestCreateTables(t *testing.T) {
	// Test users table structure
	rows, err := DB.Query("PRAGMA table_info(users)")
	if err != nil {
		t.Fatalf("Failed to get users table info: %v", err)
	}
	defer rows.Close()
	
	columns := make(map[string]bool)
	for rows.Next() {
		var cid int
		var name, dataType string
		var notNull, pk int
		var dfltValue sql.NullString
		
		err := rows.Scan(&cid, &name, &dataType, &notNull, &dfltValue, &pk)
		if err != nil {
			t.Fatalf("Failed to scan column info: %v", err)
		}
		columns[name] = true
	}
	
	expectedColumns := []string{"id", "username", "password", "role"}
	for _, col := range expectedColumns {
		if !columns[col] {
			t.Errorf("Missing column %s in users table", col)
		}
	}
	
	// Test applications table structure
	rows, err = DB.Query("PRAGMA table_info(applications)")
	if err != nil {
		t.Fatalf("Failed to get applications table info: %v", err)
	}
	defer rows.Close()
	
	columns = make(map[string]bool)
	for rows.Next() {
		var cid int
		var name, dataType string
		var notNull, pk int
		var dfltValue sql.NullString
		
		err := rows.Scan(&cid, &name, &dataType, &notNull, &dfltValue, &pk)
		if err != nil {
			t.Fatalf("Failed to scan column info: %v", err)
		}
		columns[name] = true
	}
	
	expectedAppColumns := []string{"id", "user_id", "ip_address", "port", "reason", "status", "rejection_reason", "created_at", "updated_at"}
	for _, col := range expectedAppColumns {
		if !columns[col] {
			t.Errorf("Missing column %s in applications table", col)
		}
	}
}

func TestInitAdminUser(t *testing.T) {
	setupTestDB()
	
	// Admin user should exist after InitDB
	var user models.User
	err := DB.QueryRow("SELECT id, username, password, role FROM users WHERE username = ?", "admin").
		Scan(&user.ID, &user.Username, &user.Password, &user.Role)
	
	if err != nil {
		t.Fatalf("Admin user should exist: %v", err)
	}
	
	if user.Username != "admin" {
		t.Errorf("Expected username 'admin', got %s", user.Username)
	}
	
	if user.Role != "approver" {
		t.Errorf("Expected role 'approver', got %s", user.Role)
	}
	
	// Test password hash
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte("admin"))
	if err != nil {
		t.Error("Admin password should be hashed correctly")
	}
}

func TestUserOperations(t *testing.T) {
	setupTestDB()
	
	// Test user creation
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("testpassword"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}
	
	result, err := DB.Exec("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
		"12345", string(hashedPassword), "applicant")
	if err != nil {
		t.Fatalf("Failed to insert user: %v", err)
	}
	
	userID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("Failed to get last insert ID: %v", err)
	}
	
	// Test user retrieval
	var user models.User
	err = DB.QueryRow("SELECT id, username, password, role FROM users WHERE id = ?", userID).
		Scan(&user.ID, &user.Username, &user.Password, &user.Role)
	
	if err != nil {
		t.Fatalf("Failed to retrieve user: %v", err)
	}
	
	if user.Username != "12345" {
		t.Errorf("Expected username '12345', got %s", user.Username)
	}
	
	if user.Role != "applicant" {
		t.Errorf("Expected role 'applicant', got %s", user.Role)
	}
	
	// Test password verification
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte("testpassword"))
	if err != nil {
		t.Error("Password should match")
	}
}

func TestApplicationOperations(t *testing.T) {
	setupTestDB()
	
	// Create a test user first
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("testpassword"), bcrypt.DefaultCost)
	result, err := DB.Exec("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
		"a12345", string(hashedPassword), "applicant")
	if err != nil {
		t.Fatalf("Failed to insert user: %v", err)
	}
	
	userID, _ := result.LastInsertId()
	now := time.Now()
	
	// Test application creation
	appResult, err := DB.Exec(`INSERT INTO applications 
		(user_id, ip_address, port, reason, status, rejection_reason, created_at, updated_at) 
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		userID, "192.168.1.100", 8080, "Development testing", "pending", "", now, now)
	
	if err != nil {
		t.Fatalf("Failed to insert application: %v", err)
	}
	
	appID, _ := appResult.LastInsertId()
	
	// Test application retrieval
	var app models.Application
	err = DB.QueryRow(`SELECT id, user_id, ip_address, port, reason, status, rejection_reason, created_at, updated_at 
		FROM applications WHERE id = ?`, appID).
		Scan(&app.ID, &app.UserID, &app.IPAddress, &app.Port, &app.Reason, &app.Status, 
			&app.RejectionReason, &app.CreatedAt, &app.UpdatedAt)
	
	if err != nil {
		t.Fatalf("Failed to retrieve application: %v", err)
	}
	
	if app.IPAddress != "192.168.1.100" {
		t.Errorf("Expected IP '192.168.1.100', got %s", app.IPAddress)
	}
	
	if app.Port != 8080 {
		t.Errorf("Expected port 8080, got %d", app.Port)
	}
	
	if app.Status != "pending" {
		t.Errorf("Expected status 'pending', got %s", app.Status)
	}
	
	// Test application status update
	_, err = DB.Exec("UPDATE applications SET status = ?, updated_at = ? WHERE id = ?", 
		"approved", time.Now(), appID)
	if err != nil {
		t.Fatalf("Failed to update application: %v", err)
	}
	
	// Verify update
	err = DB.QueryRow("SELECT status FROM applications WHERE id = ?", appID).Scan(&app.Status)
	if err != nil {
		t.Fatalf("Failed to retrieve updated application: %v", err)
	}
	
	if app.Status != "approved" {
		t.Errorf("Expected status 'approved', got %s", app.Status)
	}
}

func TestApplicationWithRejection(t *testing.T) {
	setupTestDB()
	
	// Create a test user
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("testpassword"), bcrypt.DefaultCost)
	result, err := DB.Exec("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
		"54321", string(hashedPassword), "applicant")
	if err != nil {
		t.Fatalf("Failed to insert user: %v", err)
	}
	
	userID, _ := result.LastInsertId()
	now := time.Now()
	
	// Create application
	appResult, err := DB.Exec(`INSERT INTO applications 
		(user_id, ip_address, port, reason, status, rejection_reason, created_at, updated_at) 
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		userID, "10.0.0.1", 22, "SSH access", "pending", "", now, now)
	
	if err != nil {
		t.Fatalf("Failed to insert application: %v", err)
	}
	
	appID, _ := appResult.LastInsertId()
	
	// Reject application
	rejectionReason := "Security policy violation"
	_, err = DB.Exec("UPDATE applications SET status = ?, rejection_reason = ?, updated_at = ? WHERE id = ?", 
		"rejected", rejectionReason, time.Now(), appID)
	if err != nil {
		t.Fatalf("Failed to reject application: %v", err)
	}
	
	// Verify rejection
	var app models.Application
	err = DB.QueryRow("SELECT status, rejection_reason FROM applications WHERE id = ?", appID).
		Scan(&app.Status, &app.RejectionReason)
	if err != nil {
		t.Fatalf("Failed to retrieve rejected application: %v", err)
	}
	
	if app.Status != "rejected" {
		t.Errorf("Expected status 'rejected', got %s", app.Status)
	}
	
	if app.RejectionReason != rejectionReason {
		t.Errorf("Expected rejection reason '%s', got %s", rejectionReason, app.RejectionReason)
	}
}

func TestApplicationQueries(t *testing.T) {
	setupTestDB()
	
	// Create test users
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("testpassword"), bcrypt.DefaultCost)
	
	// User 1
	result1, _ := DB.Exec("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
		"11111", string(hashedPassword), "applicant")
	userID1, _ := result1.LastInsertId()
	
	// User 2
	result2, _ := DB.Exec("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
		"22222", string(hashedPassword), "applicant")
	userID2, _ := result2.LastInsertId()
	
	now := time.Now()
	
	// Create multiple applications
	applications := []struct {
		userID int64
		ip     string
		port   int
		status string
	}{
		{userID1, "192.168.1.10", 8080, "pending"},
		{userID1, "192.168.1.11", 8081, "approved"},
		{userID2, "10.0.0.10", 22, "pending"},
		{userID2, "10.0.0.11", 443, "rejected"},
	}
	
	for _, app := range applications {
		_, err := DB.Exec(`INSERT INTO applications 
			(user_id, ip_address, port, reason, status, rejection_reason, created_at, updated_at) 
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			app.userID, app.ip, app.port, "Test reason", app.status, "", now, now)
		if err != nil {
			t.Fatalf("Failed to insert test application: %v", err)
		}
	}
	
	// Test query for pending applications
	var pendingCount int
	err := DB.QueryRow("SELECT COUNT(*) FROM applications WHERE status = ?", "pending").Scan(&pendingCount)
	if err != nil {
		t.Fatalf("Failed to count pending applications: %v", err)
	}
	
	if pendingCount != 2 {
		t.Errorf("Expected 2 pending applications, got %d", pendingCount)
	}
	
	// Test query for user's applications
	var userAppCount int
	err = DB.QueryRow("SELECT COUNT(*) FROM applications WHERE user_id = ?", userID1).Scan(&userAppCount)
	if err != nil {
		t.Fatalf("Failed to count user applications: %v", err)
	}
	
	if userAppCount != 2 {
		t.Errorf("Expected 2 applications for user 1, got %d", userAppCount)
	}
	
	// Test query for approved applications
	var approvedCount int
	err = DB.QueryRow("SELECT COUNT(*) FROM applications WHERE status = ?", "approved").Scan(&approvedCount)
	if err != nil {
		t.Fatalf("Failed to count approved applications: %v", err)
	}
	
	if approvedCount != 1 {
		t.Errorf("Expected 1 approved application, got %d", approvedCount)
	}
}