package models

import "time"

// User represents a user in the system.
type User struct {
	ID       int
	Username string
	Password string // This will be a bcrypt hash
	Role     string // "applicant" or "approver"
}

// Application represents a whitelist application.
type Application struct {
	ID              int
	UserID          int
	Username        string // For display purposes, joined from Users table
	IPAddress       string
	Port            int
	Reason          string
	Status          string // "pending", "approved", "rejected", "execution_failed", "removed"
	RejectionReason string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}
