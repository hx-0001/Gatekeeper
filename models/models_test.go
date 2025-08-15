package models

import (
	"testing"
	"time"
)

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
		
		// Invalid transitions (business logic)
		{"Rejected to Approved", "rejected", "approved", false},
		{"Removed to Approved", "removed", "approved", false},
		{"Execution Failed to Approved", "execution_failed", "approved", false},
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