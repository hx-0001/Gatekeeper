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
	Username        string    // For display purposes, joined from Users table
	IPAddress       string
	Port            int
	Reason          string
	Status          string    // "pending", "approved", "rejected", "execution_failed", "removed"
	RejectionReason string
	ExpiresAt       *time.Time // Optional expiration date for approved applications
	DefaultRuleID   *int       // Optional reference to a default rule
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// DefaultRule represents a global default firewall rule.
type DefaultRule struct {
	ID               int
	Name             string
	IPPattern        string    // IP pattern: specific IP, CIDR, or empty for all IPs
	Port             int
	Action           string    // "ACCEPT" or "DROP"
	Enabled          bool
	ApprovalResponse string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}
