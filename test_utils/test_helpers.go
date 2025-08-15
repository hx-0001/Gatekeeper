package testutils

import (
	"gatekeeper/database"
	"gatekeeper/models"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "github.com/mattn/go-sqlite3"
)

// SetupTestDB initializes an in-memory SQLite database for testing
func SetupTestDB() {
	database.InitDB(":memory:")
	CleanTestDB()
}

// CleanTestDB removes all test data except the admin user
func CleanTestDB() {
	database.DB.Exec("DELETE FROM applications")
	database.DB.Exec("DELETE FROM users WHERE username != 'admin'")
}

// CreateTestUser creates a user for testing purposes
func CreateTestUser(username, password, role string) (int64, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return 0, err
	}
	
	result, err := database.DB.Exec("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
		username, string(hashedPassword), role)
	if err != nil {
		return 0, err
	}
	
	return result.LastInsertId()
}

// CreateTestApplication creates an application for testing purposes
func CreateTestApplication(userID int64, ipAddress string, port int, reason, status string) (int64, error) {
	now := time.Now()
	result, err := database.DB.Exec(`INSERT INTO applications 
		(user_id, ip_address, port, reason, status, rejection_reason, created_at, updated_at) 
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		userID, ipAddress, port, reason, status, "", now, now)
	if err != nil {
		return 0, err
	}
	
	return result.LastInsertId()
}

// CreateTestApplicationWithRejection creates a rejected application with a reason
func CreateTestApplicationWithRejection(userID int64, ipAddress string, port int, reason, rejectionReason string) (int64, error) {
	now := time.Now()
	result, err := database.DB.Exec(`INSERT INTO applications 
		(user_id, ip_address, port, reason, status, rejection_reason, created_at, updated_at) 
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		userID, ipAddress, port, reason, "rejected", rejectionReason, now, now)
	if err != nil {
		return 0, err
	}
	
	return result.LastInsertId()
}

// GetUserByUsername retrieves a user by username
func GetUserByUsername(username string) (*models.User, error) {
	var user models.User
	err := database.DB.QueryRow("SELECT id, username, password, role FROM users WHERE username = ?", username).
		Scan(&user.ID, &user.Username, &user.Password, &user.Role)
	if err != nil {
		return nil, err
	}
	
	return &user, nil
}

// GetApplicationByID retrieves an application by ID
func GetApplicationByID(id int64) (*models.Application, error) {
	var app models.Application
	err := database.DB.QueryRow(`SELECT id, user_id, ip_address, port, reason, status, 
		rejection_reason, created_at, updated_at FROM applications WHERE id = ?`, id).
		Scan(&app.ID, &app.UserID, &app.IPAddress, &app.Port, &app.Reason, &app.Status, 
			&app.RejectionReason, &app.CreatedAt, &app.UpdatedAt)
	if err != nil {
		return nil, err
	}
	
	return &app, nil
}

// GetUserApplications retrieves all applications for a specific user
func GetUserApplications(userID int64) ([]models.Application, error) {
	rows, err := database.DB.Query(`SELECT id, user_id, ip_address, port, reason, status, 
		rejection_reason, created_at, updated_at FROM applications WHERE user_id = ?`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var applications []models.Application
	for rows.Next() {
		var app models.Application
		err := rows.Scan(&app.ID, &app.UserID, &app.IPAddress, &app.Port, &app.Reason, &app.Status,
			&app.RejectionReason, &app.CreatedAt, &app.UpdatedAt)
		if err != nil {
			return nil, err
		}
		applications = append(applications, app)
	}
	
	return applications, nil
}

// GetApplicationsByStatus retrieves all applications with a specific status
func GetApplicationsByStatus(status string) ([]models.Application, error) {
	rows, err := database.DB.Query(`SELECT id, user_id, ip_address, port, reason, status, 
		rejection_reason, created_at, updated_at FROM applications WHERE status = ?`, status)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var applications []models.Application
	for rows.Next() {
		var app models.Application
		err := rows.Scan(&app.ID, &app.UserID, &app.IPAddress, &app.Port, &app.Reason, &app.Status,
			&app.RejectionReason, &app.CreatedAt, &app.UpdatedAt)
		if err != nil {
			return nil, err
		}
		applications = append(applications, app)
	}
	
	return applications, nil
}

// CountUsersByRole counts users by their role
func CountUsersByRole(role string) (int, error) {
	var count int
	err := database.DB.QueryRow("SELECT COUNT(*) FROM users WHERE role = ?", role).Scan(&count)
	return count, err
}

// CountApplicationsByStatus counts applications by their status
func CountApplicationsByStatus(status string) (int, error) {
	var count int
	err := database.DB.QueryRow("SELECT COUNT(*) FROM applications WHERE status = ?", status).Scan(&count)
	return count, err
}

// UpdateApplicationStatus updates the status of an application
func UpdateApplicationStatus(appID int64, status string) error {
	_, err := database.DB.Exec("UPDATE applications SET status = ?, updated_at = ? WHERE id = ?", 
		status, time.Now(), appID)
	return err
}

// UpdateApplicationStatusWithReason updates the status and rejection reason of an application
func UpdateApplicationStatusWithReason(appID int64, status, rejectionReason string) error {
	_, err := database.DB.Exec("UPDATE applications SET status = ?, rejection_reason = ?, updated_at = ? WHERE id = ?", 
		status, rejectionReason, time.Now(), appID)
	return err
}

// VerifyPasswordHash verifies if a plain password matches the hashed password
func VerifyPasswordHash(hashedPassword, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}

// GeneratePasswordHash generates a bcrypt hash for a password
func GeneratePasswordHash(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// ValidateUsernameFormat validates if a username follows the required format
func ValidateUsernameFormat(username string) bool {
	if len(username) == 5 {
		// Check if all characters are digits (5 digits format)
		for _, char := range username {
			if char < '0' || char > '9' {
				return false
			}
		}
		return true
	} else if len(username) == 6 {
		// Check if first character is letter and rest are digits (1 letter + 5 digits)
		first := username[0]
		if (first < 'a' || first > 'z') && (first < 'A' || first > 'Z') {
			return false
		}
		
		for _, char := range username[1:] {
			if char < '0' || char > '9' {
				return false
			}
		}
		return true
	}
	
	return false
}

// ValidateIPAddress performs basic IPv4 address validation
func ValidateIPAddress(ip string) bool {
	if ip == "" {
		return false
	}
	
	// Basic format check - should contain exactly 3 dots
	dotCount := 0
	for _, char := range ip {
		if char == '.' {
			dotCount++
		}
	}
	
	return dotCount == 3
}

// ValidatePort validates if a port number is valid (1-65535)
func ValidatePort(port int) bool {
	return port >= 1 && port <= 65535
}

// CreateSampleData creates sample data for testing purposes
func CreateSampleData() error {
	// Create sample users
	users := []struct {
		username string
		password string
		role     string
	}{
		{"12345", "password123", "applicant"},
		{"67890", "password456", "applicant"},
		{"a11111", "password789", "applicant"},
		{"approver2", "approverpass", "approver"},
	}
	
	userIDs := make(map[string]int64)
	for _, user := range users {
		userID, err := CreateTestUser(user.username, user.password, user.role)
		if err != nil {
			return err
		}
		userIDs[user.username] = userID
	}
	
	// Create sample applications
	applications := []struct {
		username  string
		ip        string
		port      int
		reason    string
		status    string
	}{
		{"12345", "192.168.1.100", 8080, "Development server", "pending"},
		{"12345", "192.168.1.101", 8081, "Test environment", "approved"},
		{"67890", "10.0.0.50", 22, "SSH access", "pending"},
		{"67890", "172.16.0.10", 443, "HTTPS API", "rejected"},
		{"a11111", "192.168.2.100", 3000, "Node.js app", "approved"},
	}
	
	for _, app := range applications {
		userID := userIDs[app.username]
		if app.status == "rejected" {
			_, err := CreateTestApplicationWithRejection(userID, app.ip, app.port, app.reason, "Security policy violation")
			if err != nil {
				return err
			}
		} else {
			_, err := CreateTestApplication(userID, app.ip, app.port, app.reason, app.status)
			if err != nil {
				return err
			}
		}
	}
	
	return nil
}