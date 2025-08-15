# Gatekeeper Testing Documentation

## Overview

This document describes the testing strategy and implementation for the Gatekeeper IP whitelist management system.

## Test Structure

### Test Files Created

1. **models/models_test.go** - Unit tests for data models
2. **database/database_test.go** - Database layer tests
3. **handlers/auth_test.go** - Authentication handler tests
4. **handlers/application_test.go** - Application management handler tests
5. **integration_test.go** - End-to-end workflow tests
6. **test_utils/test_helpers.go** - Test utility functions

## Running Tests

### Quick Start

```bash
# Run all tests
make test

# Run tests with verbose output
make test-verbose

# Run specific test suites
make test-models
make test-database
make test-handlers
make test-integration
```

### Manual Test Execution

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./models ./database ./handlers

# Run specific test files
go test -v ./models
go test -v ./database
go test -v ./handlers
go test ./integration_test.go
```

## Test Categories

### 1. Unit Tests (models_test.go)

Tests data model validation and business logic:
- User struct validation
- Application struct validation  
- Status transition validation
- Field validation rules

**Key Test Cases:**
- Valid user creation with different roles
- Application status lifecycle
- Required field validation

### 2. Database Tests (database_test.go)

Tests database operations and schema:
- Database initialization
- Table creation and structure
- CRUD operations
- Data integrity constraints
- User and application queries

**Key Test Cases:**
- Database schema validation
- User registration and authentication
- Application lifecycle management
- Query result accuracy

### 3. Authentication Tests (auth_test.go)

Tests user authentication and authorization:
- User registration with format validation
- Login/logout functionality
- Password hashing and verification
- Session management
- Input validation

**Key Test Cases:**
- Valid/invalid username formats (12345, a12345)
- Password security
- Duplicate username prevention
- Authentication flow

### 4. Application Handler Tests (application_test.go)

Tests application management functionality:
- Application submission
- Approval/rejection workflows
- IP address and port validation
- Administrative functions
- User management

**Key Test Cases:**
- Application form validation
- Status updates (pending → approved/rejected)
- Admin privilege checks
- Password reset functionality

### 5. Integration Tests (integration_test.go)

Tests complete user workflows:
- End-to-end registration and login
- Complete application lifecycle
- Multi-user interactions
- Authentication middleware protection

**Key Test Cases:**
- User registration → application submission → approval workflow
- Application rejection with reasons
- Password change workflows
- Administrative user management

## Test Utilities (test_utils/test_helpers.go)

Provides helper functions for testing:
- Test database setup/cleanup
- Test data creation
- Validation helpers
- Common test operations

**Available Functions:**
- `SetupTestDB()` - Initialize test database
- `CreateTestUser()` - Create test users
- `CreateTestApplication()` - Create test applications
- `ValidateUsernameFormat()` - Username validation
- `ValidateIPAddress()` / `ValidatePort()` - Input validation

## Test Data

### Sample Users
- **admin/admin** (approver) - Default system administrator
- **12345** (applicant) - Five-digit employee ID
- **a12345** (applicant) - Letter + five digits format
- **67890** (applicant) - Alternative employee ID

### Sample Applications
- **192.168.1.100:8080** - Development server access
- **10.0.0.50:22** - SSH access request
- **172.16.0.10:443** - HTTPS API access

## Username Format Testing

The system enforces strict username validation:

✅ **Valid Formats:**
- `12345` - Exactly 5 digits
- `a12345` - One letter + 5 digits (lowercase)
- `A12345` - One letter + 5 digits (uppercase)

❌ **Invalid Formats:**
- `1234` - Too short
- `123456` - Too long  
- `ab1234` - Multiple letters
- `12-34` - Special characters
- `12 34` - Spaces

## Security Testing

Tests cover security requirements from the specification:
- Password hashing with bcrypt
- SQL injection prevention (prepared statements)
- Input validation and sanitization
- Session security
- Role-based access control

## Mock vs Real Components

### Mocked Components
- **iptables execution** - Database operations only, no actual firewall changes
- **HTTP sessions** - Simplified session testing
- **File system** - In-memory SQLite database

### Real Components
- **Database operations** - Full SQLite functionality
- **Password hashing** - Real bcrypt implementation
- **Input validation** - Actual validation logic
- **Business logic** - Complete application workflows

## Test Environment

- **Database**: In-memory SQLite (`:memory:`)
- **HTTP**: `httptest` package for request/response testing
- **Authentication**: Real bcrypt hashing
- **Isolation**: Each test uses fresh database state

## Limitations and Notes

### Current Test Limitations

1. **Session Middleware**: Some handler tests may fail without proper session setup
2. **iptables Execution**: Not tested (requires system privileges)
3. **Template Rendering**: Limited testing of HTML output
4. **Concurrent Access**: No multi-threading tests

### Integration Test Notes

- Tests simulate complete workflows but may require session mocking
- Some tests check database state directly instead of HTTP responses
- Authentication middleware protection is tested conceptually

## Extending Tests

### Adding New Tests

1. **Model Tests**: Add to `models/models_test.go`
2. **Database Tests**: Add to `database/database_test.go`  
3. **Handler Tests**: Add to respective handler test files
4. **Integration Tests**: Add to `integration_test.go`

### Test Naming Convention

- **Unit Tests**: `TestFunctionName`
- **Integration Tests**: `TestCompleteWorkflowName`
- **Edge Cases**: `TestEdgeCaseDescription`

### Best Practices

1. Use descriptive test names
2. Test both success and failure cases
3. Verify database state after operations
4. Clean up test data between tests
5. Use table-driven tests for multiple scenarios

## Continuous Integration

The test suite is designed to run in CI/CD environments:

```bash
# CI test command
go test -v -race ./...

# With coverage reporting  
go test -v -race -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html
```

## Manual Testing Checklist

After automated tests pass, verify:

1. ✅ Application builds successfully
2. ✅ Database initializes on first run
3. ✅ Admin user can log in (admin/admin)
4. ✅ New users can register with valid formats
5. ✅ Applications can be submitted and approved
6. ✅ iptables commands execute (requires sudo)
7. ✅ Session management works across requests
8. ✅ Templates render correctly

## Troubleshooting Tests

### Common Issues

**"database is locked"**
- Ensure proper database cleanup between tests
- Use separate test databases for concurrent tests

**"session not found"**
- Mock session middleware for handler tests
- Use integration tests for full session workflows

**"template not found"**
- Ensure templates directory exists
- Use relative paths in tests

**"permission denied (iptables)"**
- Expected behavior - tests don't execute actual iptables
- Use `sudo` only for manual application testing