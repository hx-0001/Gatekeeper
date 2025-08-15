# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Gatekeeper is a Go-based web application for IP whitelist management. It provides a web interface for users to request access to specific IP addresses and ports, and for administrators to approve/reject these requests. When approved, the system automatically configures iptables firewall rules.

## Build and Development Commands

### Building the Application
```bash
go build -o gatekeeper_app
```

### Running the Application
```bash
# Requires sudo for iptables access
sudo ./gatekeeper_app
```
The application runs on port 58080.

### Dependencies
```bash
go mod tidy
go mod download
```

## Architecture

### Module Structure
- `main.go` - Entry point, HTTP routing setup
- `models/` - Data structures (User, Application)
- `handlers/` - HTTP request handlers and middleware
- `database/` - SQLite database initialization and operations
- `templates/` - HTML templates for web interface
- `static/` - Static web assets

### Key Components

**Authentication & Authorization:**
- Session-based authentication using gorilla/sessions
- Two roles: "applicant" and "approver"
- Middleware chain: AuthMiddleware → ApproverMiddleware for admin routes

**Database:**
- SQLite database (`gatekeeper.db`)
- Two main tables: `users` and `applications`
- Application statuses: "pending", "approved", "rejected", "execution_failed", "removed"

**Security Features:**
- bcrypt password hashing
- Username validation (5 digits or 1 letter + 5 digits)
- SQL injection protection via prepared statements
- Session management with secure cookies

### Critical Security Context

This application requires sudo privileges to execute iptables commands for firewall management. The handlers execute system commands via `os/exec` to modify iptables rules when applications are approved.

**Default admin credentials:**
- Username: `admin`
- Password: `admin`

## Development Notes

### Database Schema
- Users table: id, username, password (bcrypt), role
- Applications table: id, user_id, ip_address, port, reason, status, rejection_reason, timestamps

### Template System
Uses Go's html/template package with templates in `templates/` directory. Templates are parsed globally at startup.

### Session Management
Cookie-based sessions with secret key "something-very-secret" (should be changed in production).