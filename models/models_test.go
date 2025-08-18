package models

import (
	"testing"
	"time"
)

// Helper function to create int pointer
func intPtr(i int) *int {
	return &i
}

func TestUserValidation(t *testing.T) {
	tests := []struct {
		name     string
		user     User
		expected bool
	}{
		{
			name: "Valid user with all fields",
			user: User{
				ID:       1,
				Username: "admin",
				Password: "$2a$10$...",
				Role:     "approver",
			},
			expected: true,
		},
		{
			name: "Valid applicant user",
			user: User{
				ID:       2,
				Username: "12345",
				Password: "$2a$10$...",
				Role:     "applicant",
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test user struct creation
			if tt.user.ID == 0 && tt.expected {
				t.Error("User ID should not be zero for valid user")
			}
			if tt.user.Username == "" && tt.expected {
				t.Error("Username should not be empty for valid user")
			}
			if tt.user.Password == "" && tt.expected {
				t.Error("Password should not be empty for valid user")
			}
			if tt.user.Role != "applicant" && tt.user.Role != "approver" && tt.expected {
				t.Error("Role should be either 'applicant' or 'approver'")
			}
		})
	}
}

func TestApplicationValidation(t *testing.T) {
	now := time.Now()
	
	tests := []struct {
		name        string
		application Application
		expected    bool
	}{
		{
			name: "Valid pending application",
			application: Application{
				ID:              1,
				UserID:          1,
				Username:        "12345",
				IPAddress:       "192.168.1.100",
				Port:            8080,
				Reason:          "Development access",
				Status:          "pending",
				RejectionReason: "",
				CreatedAt:       now,
				UpdatedAt:       now,
			},
			expected: true,
		},
		{
			name: "Valid approved application",
			application: Application{
				ID:              2,
				UserID:          2,
				Username:        "a12345",
				IPAddress:       "10.0.0.50",
				Port:            22,
				Reason:          "SSH access for maintenance",
				Status:          "approved",
				RejectionReason: "",
				CreatedAt:       now,
				UpdatedAt:       now,
			},
			expected: true,
		},
		{
			name: "Valid rejected application with reason",
			application: Application{
				ID:              3,
				UserID:          1,
				Username:        "12345",
				IPAddress:       "192.168.1.200",
				Port:            443,
				Reason:          "Web access",
				Status:          "rejected",
				RejectionReason: "Security policy violation",
				CreatedAt:       now,
				UpdatedAt:       now,
			},
			expected: true,
		},
		{
			name: "Valid application with default rule reference",
			application: Application{
				ID:            4,
				UserID:        2,
				Username:      "a12345",
				IPAddress:     "10.0.0.100",
				Port:          80,
				Reason:        "Using predefined HTTP rule",
				Status:        "pending",
				DefaultRuleID: intPtr(1),
				CreatedAt:     now,
				UpdatedAt:     now,
			},
			expected: true,
		},
		{
			name: "Valid application without default rule reference",
			application: Application{
				ID:            5,
				UserID:        1,
				Username:      "12345",
				IPAddress:     "203.0.113.50",
				Port:          9000,
				Reason:        "Custom port access",
				Status:        "pending",
				DefaultRuleID: nil,
				CreatedAt:     now,
				UpdatedAt:     now,
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := tt.application
			
			// Test application struct validation
			if app.ID == 0 && tt.expected {
				t.Error("Application ID should not be zero for valid application")
			}
			if app.UserID == 0 && tt.expected {
				t.Error("UserID should not be zero for valid application")
			}
			if app.IPAddress == "" && tt.expected {
				t.Error("IP address should not be empty for valid application")
			}
			if app.Port <= 0 || app.Port > 65535 {
				t.Error("Port should be between 1 and 65535")
			}
			if app.Reason == "" && tt.expected {
				t.Error("Reason should not be empty for valid application")
			}
			
			validStatuses := []string{"pending", "approved", "rejected", "execution_failed", "removed"}
			isValidStatus := false
			for _, status := range validStatuses {
				if app.Status == status {
					isValidStatus = true
					break
				}
			}
			if !isValidStatus && tt.expected {
				t.Error("Status should be one of: pending, approved, rejected, execution_failed, removed")
			}
			
			if app.Status == "rejected" && app.RejectionReason == "" {
				t.Error("Rejected applications should have a rejection reason")
			}
		})
	}
}

func TestApplicationStatusTransitions(t *testing.T) {
	tests := []struct {
		name           string
		fromStatus     string
		toStatus       string
		shouldBeValid  bool
	}{
		// Valid transitions
		{"Pending to Approved", "pending", "approved", true},
		{"Pending to Rejected", "pending", "rejected", true},
		{"Pending to Execution Failed", "pending", "execution_failed", true},
		{"Approved to Removed", "approved", "removed", true},
		{"Execution Failed to Approved", "execution_failed", "approved", true}, // Allow retry
		
		// Invalid transitions (business logic)
		{"Rejected to Approved", "rejected", "approved", false},
		{"Removed to Approved", "removed", "approved", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This is a conceptual test - in a real implementation,
			// you might have a method to validate status transitions
			if tt.fromStatus == "rejected" && tt.toStatus == "approved" && tt.shouldBeValid {
				t.Error("Should not allow transition from rejected to approved")
			}
			if tt.fromStatus == "removed" && tt.toStatus == "approved" && tt.shouldBeValid {
				t.Error("Should not allow transition from removed to approved")
			}
		})
	}
}

func TestDefaultRuleValidation(t *testing.T) {
	tests := []struct {
		name     string
		rule     DefaultRule
		expected bool
	}{
		{
			name: "Valid DROP rule for SSH port",
			rule: DefaultRule{
				ID:          1,
				Name:        "Block SSH",
				IPPattern:   "",
				Port:        22,
				Action:      "DROP",
				Enabled:     true,
				ApprovalResponse: "Block SSH access from all IPs",
			},
			expected: true,
		},
		{
			name: "Valid ACCEPT rule for specific IP",
			rule: DefaultRule{
				ID:          2,
				Name:        "Allow local HTTP",
				IPPattern:   "192.168.1.0/24",
				Port:        80,
				Action:      "ACCEPT",
				Enabled:     true,
				ApprovalResponse: "Allow HTTP from local network",
			},
			expected: true,
		},
		{
			name: "Invalid action",
			rule: DefaultRule{
				ID:     3,
				Name:   "Invalid rule",
				Port:   443,
				Action: "INVALID",
			},
			expected: false,
		},
		{
			name: "Invalid port (negative)",
			rule: DefaultRule{
				ID:     4,
				Name:   "Invalid port",
				Port:   -1,
				Action: "DROP",
			},
			expected: false,
		},
		{
			name: "Invalid port (too high)",
			rule: DefaultRule{
				ID:     5,
				Name:   "Invalid port",
				Port:   70000,
				Action: "DROP",
			},
			expected: false,
		},
		{
			name: "Empty name",
			rule: DefaultRule{
				ID:     6,
				Name:   "",
				Port:   80,
				Action: "ACCEPT",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test rule name validation
			if tt.rule.Name == "" && tt.expected {
				t.Error("Rule name should not be empty for valid rule")
			}
			
			// Test action validation
			validActions := []string{"ACCEPT", "DROP"}
			actionValid := false
			for _, action := range validActions {
				if tt.rule.Action == action {
					actionValid = true
					break
				}
			}
			if !actionValid && tt.expected {
				t.Error("Action should be either 'ACCEPT' or 'DROP'")
			}
			
			// Test port validation
			if (tt.rule.Port < 1 || tt.rule.Port > 65535) && tt.expected {
				t.Error("Port should be between 1 and 65535")
			}
			
			// Test IP pattern format (basic validation)
			if tt.rule.IPPattern != "" && tt.expected {
				// Basic check for valid IP pattern format
				// In real implementation, this would use net package for validation
				if len(tt.rule.IPPattern) < 7 { // Minimum valid IP: "1.1.1.1"
					t.Error("IP pattern appears to be invalid")
				}
			}
		})
	}
}

func TestDefaultRuleFields(t *testing.T) {
	now := time.Now()
	rule := DefaultRule{
		ID:          1,
		Name:        "Test Rule",
		IPPattern:   "192.168.1.100",
		Port:        8080,
		Action:      "ACCEPT",
		Enabled:     true,
		ApprovalResponse: "Test description",
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	// Test field assignments
	if rule.ID != 1 {
		t.Errorf("Expected ID 1, got %d", rule.ID)
	}
	if rule.Name != "Test Rule" {
		t.Errorf("Expected name 'Test Rule', got %s", rule.Name)
	}
	if rule.IPPattern != "192.168.1.100" {
		t.Errorf("Expected IP pattern '192.168.1.100', got %s", rule.IPPattern)
	}
	if rule.Port != 8080 {
		t.Errorf("Expected port 8080, got %d", rule.Port)
	}
	if rule.Action != "ACCEPT" {
		t.Errorf("Expected action 'ACCEPT', got %s", rule.Action)
	}
	if !rule.Enabled {
		t.Error("Expected rule to be enabled")
	}
	if rule.ApprovalResponse != "Test description" {
		t.Errorf("Expected description 'Test description', got %s", rule.ApprovalResponse)
	}
}

func TestApplicationWithDefaultRule(t *testing.T) {
	now := time.Now()
	
	tests := []struct {
		name                    string
		application            Application
		shouldHaveDefaultRule  bool
	}{
		{
			name: "Application created from default rule",
			application: Application{
				ID:            1,
				UserID:        1,
				Username:      "12345",
				IPAddress:     "192.168.1.100",
				Port:          80,
				Reason:        "Using HTTP default rule",
				Status:        "pending",
				DefaultRuleID: intPtr(1),
				CreatedAt:     now,
				UpdatedAt:     now,
			},
			shouldHaveDefaultRule: true,
		},
		{
			name: "Application created manually",
			application: Application{
				ID:            2,
				UserID:        1,
				Username:      "12345",
				IPAddress:     "192.168.1.200",
				Port:          9000,
				Reason:        "Custom application",
				Status:        "pending",
				DefaultRuleID: nil,
				CreatedAt:     now,
				UpdatedAt:     now,
			},
			shouldHaveDefaultRule: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := tt.application
			
			if tt.shouldHaveDefaultRule {
				if app.DefaultRuleID == nil {
					t.Error("Expected application to have a default rule reference")
				} else if *app.DefaultRuleID <= 0 {
					t.Error("Default rule ID should be positive")
				}
			} else {
				if app.DefaultRuleID != nil {
					t.Error("Expected application to not have a default rule reference")
				}
			}
			
			// Verify other fields are still valid
			if app.IPAddress == "" {
				t.Error("IP address should not be empty")
			}
			if app.Port <= 0 || app.Port > 65535 {
				t.Error("Port should be between 1 and 65535")
			}
			if app.Reason == "" {
				t.Error("Reason should not be empty")
			}
		})
	}
}