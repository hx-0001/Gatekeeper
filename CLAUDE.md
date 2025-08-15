# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Gatekeeper is a Go-based web application for IP whitelist management. It provides a web interface for users to request access to specific IP addresses and ports, and for administrators to approve/reject these requests. When approved, the system automatically configures iptables firewall rules.

## Build and Development Commands

### Using Makefile (Recommended)
The project includes a comprehensive Makefile with useful targets:

```bash
# Build the application
make build

# Run all tests
make test
make test-verbose    # with verbose output

# Run specific test suites
make test-models     # model validation tests
make test-database   # database operation tests
make test-handlers   # HTTP handler tests
make test-integration # end-to-end workflow tests

# Build and run (requires sudo)
make run

# Development workflow
make dev            # clean + build + test
make clean          # remove build artifacts
make coverage       # generate coverage report
```

### Manual Commands
```bash
# Build the application
go build -o gatekeeper_app

# Run with default configuration
sudo ./gatekeeper_app

# Run with custom configuration file
sudo ./gatekeeper_app -config=custom-config.json

# Dependencies
go mod tidy
go mod download

# Alternative test runner
go run run_tests.go
```

### Configuration
The application now supports configuration files:
- Copy `config.example.json` to `config.json` and modify as needed
- Use `-config` flag to specify custom config file path
- If no config file exists, defaults will be used
- See README.md for detailed configuration documentation

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

**Important Files:**
- `gatekeeper.db` - SQLite database (created on first run)
- `run_tests.go` - Alternative test runner with detailed output
- `README.md` - Comprehensive project documentation including configuration and testing
- `requirement.md` - Original project requirements
- `config.example.json` - Configuration file template

## Development Notes

### Database Schema
- Users table: id, username, password (bcrypt), role
- Applications table: id, user_id, ip_address, port, reason, status, rejection_reason, timestamps

### Template System
Uses Go's html/template package with templates in `templates/` directory. Templates are parsed globally at startup.

### Session Management
Cookie-based sessions with secret key "something-very-secret" (should be changed in production).

## Testing

The project has comprehensive test coverage across all components:

### Test Structure
- `models/models_test.go` - Data model validation tests
- `database/database_test.go` - Database operations and schema tests  
- `handlers/auth_test.go` - Authentication handler tests
- `handlers/application_test.go` - Application management handler tests
- `integration_test.go` - End-to-end workflow tests
- `test_utils/test_helpers.go` - Test utility functions

### Key Test Categories
- **Unit Tests**: Model validation and business logic
- **Database Tests**: CRUD operations and data integrity  
- **Handler Tests**: HTTP endpoints and middleware
- **Integration Tests**: Complete user workflows

### Username Format Validation Testing
The system enforces strict username validation:
- Valid: `12345` (5 digits), `a12345` (1 letter + 5 digits)
- Invalid: Different lengths, multiple letters, special characters

See README.md Testing section for detailed testing documentation and troubleshooting.

## Development Workflow

### Before Making Changes
1. Run `make test` to ensure all tests pass
2. Review existing patterns in the codebase before adding new features
3. Check if similar functionality exists before implementing from scratch

### After Making Changes
1. Run `make test-verbose` to verify all tests still pass
2. Use `make coverage` to check test coverage for new code
3. Build with `make build` to ensure compilation succeeds
4. For handler changes, test manually with `make run` (requires sudo)

### Code Patterns
- HTTP handlers follow the pattern: `func HandlerName(w http.ResponseWriter, r *http.Request)`
- Database operations use prepared statements for security
- Authentication uses session-based middleware chains
- Templates are pre-parsed at startup for performance

### Go Version Requirements
- Minimum: Go 1.23.0
- Current toolchain: Go 1.24.5 (as per go.mod)
- CGO required for SQLite driver (go-sqlite3)

## Configuration

The application uses JSON configuration files to replace hardcoded values. This allows customization without code changes.

### Configuration Files
- `config.example.json` - Template with default values
- `config.prod.example.json` - Production environment template
- Create your own `config.json` from the examples

### Configuration Structure

```json
{
  "server": {
    "port": ":58080",           // Server listen port
    "static_dir": "static",     // Static files directory
    "log_level": "info"         // Logging level
  },
  "database": {
    "path": "./gatekeeper.db",  // SQLite database file path
    "driver": "sqlite3"         // Database driver
  },
  "session": {
    "secret_key": "secret",     // Session encryption key (CHANGE THIS!)
    "name": "session-name",     // Session cookie name
    "max_age": 86400           // Session duration in seconds
  },
  "templates": {
    "directory": "templates",   // HTML templates directory
    "pattern": "*.html"         // Template file pattern
  },
  "admin": {
    "username": "admin",        // Default admin username
    "password": "admin",        // Default admin password (CHANGE THIS!)
    "role": "approver"          // Admin user role
  },
  "security": {
    "username_pattern": "^([a-z]\\d{5}|\\d{5})$",  // Username validation regex
    "allowed_roles": ["applicant", "approver"],        // Valid user roles
    "bcrypt_cost": 12                                   // Password hashing cost
  }
}
```

### Usage Examples

```bash
# Use default configuration (config.json or built-in defaults)
sudo ./gatekeeper_app

# Specify custom configuration file
sudo ./gatekeeper_app -config=/etc/gatekeeper/production.json

# Development with custom port
sudo ./gatekeeper_app -config=dev-config.json
```

### Configuration Precedence
1. Command-line specified config file
2. `config.json` in current directory (if exists)
3. Built-in defaults (if no config file found)

### Security Considerations
- Always change default admin credentials
- Use strong, random session secret keys in production
- Consider higher bcrypt cost (14+) for production
- Use absolute paths for production deployments