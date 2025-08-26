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

# Run with custom config
make run-config CONFIG=path/to/config.json

# Development workflow
make dev            # clean + build + test
make clean          # remove build artifacts
make coverage       # generate coverage report
make config         # create config.json from example
make benchmark      # run performance benchmarks
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

# Run single test file
go test -v ./models/models_test.go
go test -v ./database/database_test.go
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
- Main tables: `users`, `applications`, `default_rules`
- Application statuses: "pending", "approved", "rejected", "execution_failed", "removed"
- Default rules support global firewall policies with configurable priority

**Security Features:**
- bcrypt password hashing
- Username validation (5 digits or 1 letter + 5 digits)
- SQL injection protection via prepared statements
- Session management with secure cookies
- Default firewall rules with priority system

### Critical Security Context

This application requires sudo privileges to execute iptables commands for firewall management. The handlers execute system commands via `os/exec` to modify iptables rules when applications are approved or when managing default firewall rules. The system implements a two-tier priority system:
- High priority: Approved application rules (inserted at front with `iptables -I`)  
- Low priority: Default global rules (appended with `iptables -A`)

**Default admin credentials:**
- Username: `admin`  
- Password: `admin`

**Important Files:**
- `gatekeeper.db` - SQLite database (created on first run)
- `run_tests.go` - Alternative test runner with detailed output
- `README.md` - Comprehensive project documentation including configuration and testing
- `requirement.md` - Original project requirements
- `config.example.json` - Configuration file template
- `demo_default_rules.md` - Documentation for default rules functionality

## Development Notes

### Database Schema
- Users table: id, username, password (bcrypt), role
- Applications table: id, user_id, ip_address, port, reason, status, rejection_reason, timestamps
- Default_rules table: id, name, ip_pattern, port, action, enabled, description, timestamps

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
- Embedded static files and templates using `go:embed` directives
- Default rules are loaded asynchronously at startup to prevent blocking server start

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

# AI自我复盘改进规则框架

## 目的
当AI犯错或执行结果不满足用户预期，经修改后问题解决时，自我复盘总结经验规则，避免重复犯错。

## 强制复盘要求
**CRITICAL - 必须执行**: 每当完成重要任务后，特别是用户指出实现问题时，必须主动进行复盘：

### 1. 任务完成强制检查
- 所有复杂实现任务都必须添加最终todo项："任务复盘和改进规则评估"
- 在标记任务完成前，必须验证是否完整满足用户需求
- 不能仅完成部分功能就认为任务结束

### 2. 错误学习强制触发
当用户指出实现不符合预期时，必须立即询问：
```
📝 是否需要生成改进规则来避免类似错误？
[Y] 生成规则文件
[S] 仅显示内容  
[N] 跳过
```

### 3. 强制复盘情况
- 用户明确表示："你的任务完成得不符合预期"
- 需要修复或重新实现大部分代码  
- 实现不完整，遗漏重要部分
- 涉及核心功能的多文件复杂更改
- 用户指出了通用性问题（如"这是一个通用问题"）

## 触发条件
- AI代码被用户指出问题 or AI自我认为犯错 or AI执行任务不符合用户预期
- 经过修改后问题已解决
- 问题具有通用性

## 规则模板

```markdown
# [问题类型] - RULE-{日期}-{序号}

## 错误场景
- **用户需求**: [需求描述]
- **AI错误**: [错误实现]
- **问题**: [具体问题表现]

## 正确做法
- **应该**: [正确做法]
- **避免**: [错误做法]
- **检查**: [关键检查点]

## 代码示例
### ❌ 错误
```code
[错误代码]
```

### ✅ 正确
```code
[正确代码]
```
```

## 工作流程

### 问题修复完成后提示
```
📝 是否生成改进规则？
[Y] 生成规则文件
[S] 仅显示内容  
[N] 跳过

选择: _
```

### 规则存储
```
.当前工具定义的规则目录名称/
├── others/      # 项目特定
└── temp/       # 临时规则
```

## 规则应用
编码前AI应检查相关规则并声明：
```
已检查规则库，注意以下问题：
- RULE-20250101-001: [问题描述]
- RULE-20250105-002: [问题描述]
```