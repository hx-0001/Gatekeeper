package database

import (
	"database/sql"
	"log"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "github.com/mattn/go-sqlite3"
	"gatekeeper/config"
	"gatekeeper/models"
)

var DB *sql.DB
var dbConfig *config.Config

// InitDB initializes the database connection and creates tables if they don't exist.
func InitDB(dataSourceName string) {
	// Get current configuration
	dbConfig = config.GetConfig()
	
	var err error
	DB, err = sql.Open(dbConfig.Database.Driver, dataSourceName)
	if err != nil {
		log.Fatalf("Error opening database: %v", err)
	}

	if err = DB.Ping(); err != nil {
		log.Fatalf("Error pinging database: %v", err)
	}

	createTables()
	migrateDatabase()
	initAdminUser()
}

func createTables() {
	usersTable := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL,
		role TEXT NOT NULL
	);`

	applicationsTable := `
	CREATE TABLE IF NOT EXISTS applications (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		ip_address TEXT NOT NULL,
		port INTEGER NOT NULL,
		reason TEXT NOT NULL,
		status TEXT NOT NULL,
		rejection_reason TEXT,
		expires_at DATETIME,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL,
		FOREIGN KEY(user_id) REFERENCES users(id)
	);`

	defaultRulesTable := `
	CREATE TABLE IF NOT EXISTS default_rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		ip_pattern TEXT,
		port INTEGER NOT NULL,
		action TEXT NOT NULL,
		enabled BOOLEAN NOT NULL DEFAULT 1,
		description TEXT,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL
	);`

	if _, err := DB.Exec(usersTable); err != nil {
		log.Fatalf("Could not create users table: %v", err)
	}

	if _, err := DB.Exec(applicationsTable); err != nil {
		log.Fatalf("Could not create applications table: %v", err)
	}

	if _, err := DB.Exec(defaultRulesTable); err != nil {
		log.Fatalf("Could not create default_rules table: %v", err)
	}
}

func migrateDatabase() {
	// Check which columns exist
	var expiresAtExists, defaultRuleIdExists bool
	rows, err := DB.Query("PRAGMA table_info(applications)")
	if err != nil {
		log.Printf("Warning: Could not check table info: %v", err)
		return
	}
	defer rows.Close()
	
	for rows.Next() {
		var cid int
		var name, dataType string
		var notNull, pk bool
		var defaultValue sql.NullString
		
		err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &pk)
		if err != nil {
			continue
		}
		
		if name == "expires_at" {
			expiresAtExists = true
		}
		if name == "default_rule_id" {
			defaultRuleIdExists = true
		}
	}
	
	// Add expires_at column if it doesn't exist
	if !expiresAtExists {
		_, err := DB.Exec("ALTER TABLE applications ADD COLUMN expires_at DATETIME")
		if err != nil {
			log.Printf("Warning: Could not add expires_at column: %v", err)
		} else {
			log.Println("Added expires_at column to applications table")
		}
	}
	
	// Add default_rule_id column if it doesn't exist
	if !defaultRuleIdExists {
		_, err := DB.Exec("ALTER TABLE applications ADD COLUMN default_rule_id INTEGER REFERENCES default_rules(id)")
		if err != nil {
			log.Printf("Warning: Could not add default_rule_id column: %v", err)
		} else {
			log.Println("Added default_rule_id column to applications table")
		}
	}
}

func initAdminUser() {
	var userCount int
	err := DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&userCount)
	if err != nil {
		log.Fatalf("Could not query user count: %v", err)
	}

	// If no users exist, create the admin user
	if userCount == 0 {
		username := dbConfig.Admin.Username
		password := dbConfig.Admin.Password
		role := dbConfig.Admin.Role

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), dbConfig.Security.BcryptCost)
		if err != nil {
			log.Fatalf("Could not hash password: %v", err)
		}

		stmt, err := DB.Prepare("INSERT INTO users(username, password, role) VALUES(?, ?, ?)")
		if err != nil {
			log.Fatalf("Could not prepare admin user insert statement: %v", err)
		}
		defer stmt.Close()

		if _, err := stmt.Exec(username, string(hashedPassword), role); err != nil {
			log.Fatalf("Could not insert admin user: %v", err)
		}
		log.Printf("Admin user '%s' created successfully.", username)
	}
}

// GetAllUsers retrieves all users from the database
func GetAllUsers() ([]models.User, error) {
	rows, err := DB.Query("SELECT id, username, role FROM users ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		var user models.User
		err := rows.Scan(&user.ID, &user.Username, &user.Role)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	return users, nil
}

// ResetPassword resets a user's password to a default value
func ResetPassword(userID int, defaultPassword string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(defaultPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	_, err = DB.Exec("UPDATE users SET password = ? WHERE id = ?", string(hashedPassword), userID)
	return err
}

// GetUserByID retrieves a user by ID
func GetUserByID(userID int) (models.User, error) {
	var user models.User
	err := DB.QueryRow("SELECT id, username, role FROM users WHERE id = ?", userID).Scan(&user.ID, &user.Username, &user.Role)
	return user, err
}

// GetExpiredApplications retrieves all approved applications that have expired
func GetExpiredApplications() ([]models.Application, error) {
	query := `
		SELECT id, user_id, ip_address, port, reason, status, expires_at, created_at, updated_at
		FROM applications 
		WHERE status = 'approved' AND expires_at IS NOT NULL AND expires_at <= ?
		ORDER BY expires_at ASC`
	
	rows, err := DB.Query(query, time.Now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var applications []models.Application
	for rows.Next() {
		var app models.Application
		err := rows.Scan(&app.ID, &app.UserID, &app.IPAddress, &app.Port, &app.Reason, &app.Status, &app.ExpiresAt, &app.CreatedAt, &app.UpdatedAt)
		if err != nil {
			return nil, err
		}
		applications = append(applications, app)
	}

	return applications, nil
}

// MarkApplicationExpired marks an application as expired and removes it from the firewall
func MarkApplicationExpired(appID int) error {
	_, err := DB.Exec("UPDATE applications SET status = 'expired', updated_at = ? WHERE id = ?", time.Now(), appID)
	return err
}

// GetAllDefaultRules retrieves all default rules from the database
func GetAllDefaultRules() ([]models.DefaultRule, error) {
	query := `
		SELECT id, name, ip_pattern, port, action, enabled, description, created_at, updated_at
		FROM default_rules
		ORDER BY created_at DESC`
	
	rows, err := DB.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []models.DefaultRule
	for rows.Next() {
		var rule models.DefaultRule
		err := rows.Scan(&rule.ID, &rule.Name, &rule.IPPattern, &rule.Port, &rule.Action,
			&rule.Enabled, &rule.Description, &rule.CreatedAt, &rule.UpdatedAt)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}

	return rules, nil
}

// GetEnabledDefaultRules retrieves only enabled default rules
func GetEnabledDefaultRules() ([]models.DefaultRule, error) {
	query := `
		SELECT id, name, ip_pattern, port, action, enabled, description, created_at, updated_at
		FROM default_rules
		WHERE enabled = 1
		ORDER BY created_at ASC`
	
	rows, err := DB.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []models.DefaultRule
	for rows.Next() {
		var rule models.DefaultRule
		err := rows.Scan(&rule.ID, &rule.Name, &rule.IPPattern, &rule.Port, &rule.Action,
			&rule.Enabled, &rule.Description, &rule.CreatedAt, &rule.UpdatedAt)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}

	return rules, nil
}

// GetDefaultRuleByID retrieves a default rule by ID
func GetDefaultRuleByID(id int) (models.DefaultRule, error) {
	var rule models.DefaultRule
	query := `
		SELECT id, name, ip_pattern, port, action, enabled, description, created_at, updated_at
		FROM default_rules WHERE id = ?`
	
	err := DB.QueryRow(query, id).Scan(&rule.ID, &rule.Name, &rule.IPPattern, &rule.Port,
		&rule.Action, &rule.Enabled, &rule.Description, &rule.CreatedAt, &rule.UpdatedAt)
	
	return rule, err
}

// CreateDefaultRule creates a new default rule
func CreateDefaultRule(rule models.DefaultRule) (int64, error) {
	query := `
		INSERT INTO default_rules (name, ip_pattern, port, action, enabled, description, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	
	now := time.Now()
	result, err := DB.Exec(query, rule.Name, rule.IPPattern, rule.Port, rule.Action,
		rule.Enabled, rule.Description, now, now)
	if err != nil {
		return 0, err
	}
	
	return result.LastInsertId()
}

// UpdateDefaultRule updates an existing default rule
func UpdateDefaultRule(rule models.DefaultRule) error {
	query := `
		UPDATE default_rules 
		SET name = ?, ip_pattern = ?, port = ?, action = ?, enabled = ?, description = ?, updated_at = ?
		WHERE id = ?`
	
	_, err := DB.Exec(query, rule.Name, rule.IPPattern, rule.Port, rule.Action,
		rule.Enabled, rule.Description, time.Now(), rule.ID)
	
	return err
}

// DeleteDefaultRule deletes a default rule by ID
func DeleteDefaultRule(id int) error {
	_, err := DB.Exec("DELETE FROM default_rules WHERE id = ?", id)
	return err
}
