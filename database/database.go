package database

import (
	"database/sql"
	"log"

	"golang.org/x/crypto/bcrypt"
	_ "github.com/mattn/go-sqlite3"
	"gatekeeper/models"
)

var DB *sql.DB

// InitDB initializes the database connection and creates tables if they don't exist.
func InitDB(dataSourceName string) {
	var err error
	DB, err = sql.Open("sqlite3", dataSourceName)
	if err != nil {
		log.Fatalf("Error opening database: %v", err)
	}

	if err = DB.Ping(); err != nil {
		log.Fatalf("Error pinging database: %v", err)
	}

	createTables()
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
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL,
		FOREIGN KEY(user_id) REFERENCES users(id)
	);`

	if _, err := DB.Exec(usersTable); err != nil {
		log.Fatalf("Could not create users table: %v", err)
	}

	if _, err := DB.Exec(applicationsTable); err != nil {
		log.Fatalf("Could not create applications table: %v", err)
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
		username := "admin"
		password := "admin"
		role := "approver"

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
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
		log.Println("Admin user created successfully.")
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
