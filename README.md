# Gatekeeper IP 白名单申请系统

[![Go Version](https://img.shields.io/badge/Go-1.23%2B-blue.svg)](https://golang.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg)](#testing)

Gatekeeper 是一个基于 Web 的 IP 白名单申请和管理系统。它旨在为需要临时或永久开放服务器特定端口访问权限的用户提供一个简单、可审计的申请流程，同时为管理员提供一个方便的审批和管理界面。

## 目录

- [主要功能](#主要功能-1)
- [快速开始](#快速开始)
- [安装与构建](#安装与构建)
- [配置](#配置)
- [使用方法](#使用方法)
- [开发](#开发)
- [测试](#测试)
- [部署](#部署)
- [安全注意事项](#安全注意事项)
- [贡献指南](#贡献指南)
- [许可证](#许可证)

## 主要功能

### 🔐 用户系统
- 用户注册和登录功能
- 用户角色分为申请人 (applicant) 和审批人 (approver)
- 用户可以自行修改密码

### 📝 申请流程
- 申请人可以提交 IP 地址和端口的白名单申请
- 申请时需要填写申请理由
- 申请人可以查看自己提交的所有申请及其当前状态

### ✅ 审批流程
- 审批人可以查看所有待处理的申请
- 审批人可以批准或拒绝申请
- 批准申请后，系统会自动调用 `iptables` 命令将相应的 IP 和端口添加到防火墙规则中
- 拒绝申请时，需要填写拒绝理由

### ⚙️ 管理功能
- 审批人可以查看和管理系统中的所有用户
- 审批人可以重置任何用户的密码
- 完全可配置的系统设置

## 技术栈

- **后端**: Go 1.23+
- **数据库**: SQLite 
- **Web 框架**: Go 标准库 `net/http`
- **会话管理**: `gorilla/sessions`
- **密码加密**: `golang.org/x/crypto/bcrypt`
- **配置**: JSON 格式配置文件

## 快速开始

```bash
# 克隆项目
git clone <repository_url>
cd Gatekeeper

# 构建应用
make build

# 创建配置文件
make config

# 运行应用（需要 sudo 权限）
sudo ./gatekeeper_app
```

访问 http://localhost:58080，使用默认管理员账户登录：
- 用户名: `admin`
- 密码: `admin` （请立即修改）

## 环境要求

- **Go**: 版本 1.23.0 或更高
- **C 编译器**: `go-sqlite3` 依赖 CGO，需要 `gcc` 或类似编译器
- **sudo 权限**: 应用需要执行 `iptables` 命令来修改防火墙规则

## 安装与构建

### 方法一：使用 Makefile（推荐）

```bash
# 克隆仓库
git clone <repository_url>
cd Gatekeeper

# 安装依赖
go mod download

# 构建应用
make build

# 查看所有可用命令
make help
```

### 方法二：手动构建

```bash
# 克隆仓库
git clone <repository_url>
cd Gatekeeper

# 构建应用
go build -o gatekeeper_app

# 运行应用
sudo ./gatekeeper_app
```

## 配置

Gatekeeper 支持通过 JSON 配置文件进行灵活配置，无需修改代码即可自定义各种设置。

### 配置文件生成

```bash
# 从模板创建配置文件
make config
# 或者手动复制
cp config.example.json config.json
```

### 配置文件结构

```json
{
  "server": {
    "port": ":58080",           // 服务器监听端口
    "static_dir": "static",     // 静态文件目录
    "log_level": "info"         // 日志级别
  },
  "database": {
    "path": "./gatekeeper.db",  // SQLite 数据库路径
    "driver": "sqlite3"         // 数据库驱动
  },
  "session": {
    "secret_key": "your-secret-key",  // Session 加密密钥（请修改！）
    "name": "session-name",           // Session Cookie 名称
    "max_age": 86400                  // Session 过期时间（秒）
  },
  "templates": {
    "directory": "templates",   // HTML 模板目录
    "pattern": "*.html"         // 模板文件匹配模式
  },
  "admin": {
    "username": "admin",        // 默认管理员用户名
    "password": "admin",        // 默认管理员密码（请修改！）
    "role": "approver"          // 管理员角色
  },
  "security": {
    "username_pattern": "^([a-z]\\d{5}|\\d{5})$",  // 用户名验证正则
    "allowed_roles": ["applicant", "approver"],     // 允许的用户角色
    "bcrypt_cost": 12                               // 密码加密强度
  }
}
```

### 配置文件使用

```bash
# 使用默认配置（config.json 或内置默认值）
sudo ./gatekeeper_app

# 使用指定配置文件
sudo ./gatekeeper_app -config=/path/to/config.json

# 使用 Makefile 运行
make run                           # 使用默认配置
make run-config CONFIG=my.json     # 使用指定配置
```

### 配置优先级

1. 命令行指定的配置文件 (`-config` 参数)
2. 当前目录的 `config.json` 文件（如果存在）
3. 内置默认配置（如果没有找到配置文件）

### 生产环境配置示例

```json
{
  "server": {
    "port": ":8080",
    "static_dir": "/var/www/gatekeeper/static",
    "log_level": "warn"
  },
  "database": {
    "path": "/var/lib/gatekeeper/gatekeeper.db"
  },
  "session": {
    "secret_key": "生成-64位随机字符串-用于生产环境",
    "name": "gatekeeper-prod-session",
    "max_age": 28800
  },
  "templates": {
    "directory": "/var/www/gatekeeper/templates"
  },
  "admin": {
    "username": "administrator",
    "password": "首次登录后立即修改"
  },
  "security": {
    "bcrypt_cost": 14
  }
}
```

## 使用方法

### 基本使用流程

1. **启动服务**
   ```bash
   # 使用默认配置启动
   sudo ./gatekeeper_app
   
   # 使用自定义配置启动
   sudo ./gatekeeper_app -config=production.json
   ```

2. **首次访问**
   - 在浏览器中打开 `http://localhost:58080`（或配置文件中指定的端口）
   - 使用默认管理员账户登录：
     - 用户名: `admin`（或配置文件中指定的用户名）
     - 密码: `admin`（或配置文件中指定的密码）
   - **⚠️ 首次登录后请立即修改管理员密码**

3. **用户注册**
   - 新用户可以通过注册页面自行注册
   - 用户名格式：5位数字（如 `12345`）或 1个字母+5位数字（如 `a12345`）
   - 注册后的用户默认为"申请人"角色

4. **申请白名单**
   - 使用申请人账户登录
   - 点击"申请"导航链接
   - 填写需要加入白名单的 IP 地址、端口和申请原因
   - 提交申请

5. **审批申请**
   - 使用审批人账户登录
   - 在首页仪表盘查看所有"待处理"的申请
   - 点击"批准"或"拒绝"按钮进行操作
   - 拒绝时需要填写拒绝理由

### Makefile 命令

```bash
make help            # 查看所有可用命令
make build           # 构建应用
make test            # 运行所有测试
make test-verbose    # 运行测试（详细输出）
make run             # 构建并运行应用
make config          # 创建默认配置文件
make clean           # 清理构建文件
make coverage        # 生成测试覆盖率报告
```

## 开发

### 项目结构

```
Gatekeeper/
├── main.go                 # 应用入口点
├── config/                 # 配置管理
│   └── config.go
├── models/                 # 数据模型
│   ├── models.go
│   └── models_test.go
├── database/              # 数据库操作
│   ├── database.go
│   └── database_test.go
├── handlers/              # HTTP 处理器
│   ├── handlers.go
│   ├── auth_test.go
│   └── application_test.go
├── templates/             # HTML 模板
├── static/               # 静态文件
├── test_utils/           # 测试工具
├── config.example.json   # 配置文件模板
├── Makefile             # 构建脚本
└── README.md           # 项目文档
```

### 开发工作流

```bash
# 克隆并设置项目
git clone <repository_url>
cd Gatekeeper
go mod download

# 开发循环
make dev          # 清理 + 构建 + 测试
make test-verbose # 详细测试输出
make run          # 运行应用进行手动测试

# 代码质量
make coverage     # 生成测试覆盖率报告
```

### 代码规范

- 使用 Go 标准格式化: `go fmt`
- 遵循 Go 命名约定
- 为公共函数编写文档注释
- 为新功能编写相应测试
- 使用配置而非硬编码值

## 测试

本项目包含完整的测试套件，覆盖所有主要功能模块，确保代码质量和系统稳定性。

### 快速开始

```bash
# 运行所有测试
make test

# 详细输出测试
make test-verbose

# 运行特定测试模块
make test-models      # 数据模型测试
make test-database    # 数据库操作测试
make test-handlers    # HTTP 处理器测试
make test-integration # 端到端集成测试

# 生成覆盖率报告
make coverage
```

### 手动测试执行

```bash
# 运行所有测试
go test ./...

# 运行带覆盖率的测试
go test -cover ./models ./database ./handlers

# 运行特定测试文件
go test -v ./models
go test -v ./database
go test -v ./handlers
go test -v ./integration_test.go

# 运行特定测试函数
go test -v -run TestLoginHandler ./handlers
```

### 测试架构

项目测试分为以下几个层次：

#### 1. 单元测试 (`models/models_test.go`)
测试数据模型验证和业务逻辑：
- **User 结构验证**: 用户名格式、角色验证
- **Application 结构验证**: IP地址、端口、状态验证
- **状态转换验证**: 申请状态生命周期管理
- **字段验证规则**: 必填字段和格式约束

**关键测试用例**:
```go
// 用户名格式测试
{"12345", true},     // 5位数字
{"a12345", true},    // 1字母+5数字
{"A12345", false},   // 大写字母无效
{"abc123", false},   // 多字母无效

// 申请状态转换测试
{"pending", "approved", true},
{"pending", "rejected", true}, 
{"rejected", "approved", false}, // 不允许
```

#### 2. 数据库测试 (`database/database_test.go`)
测试数据库操作和模式完整性：
- **数据库初始化**: 表创建和结构验证
- **CRUD 操作**: 增删改查功能测试
- **数据完整性**: 约束和关系验证
- **查询准确性**: 复杂查询结果验证

**关键测试场景**:
- 管理员用户自动创建
- 用户注册和认证流程
- 申请生命周期管理
- 数据库模式验证

#### 3. 认证测试 (`handlers/auth_test.go`)
测试用户认证和授权：
- **用户注册**: 格式验证和重复检查
- **登录/登出**: 密码验证和会话管理
- **密码安全**: bcrypt 哈希和验证
- **会话管理**: Session 创建和销毁

**用户名格式验证测试**:
```
✅ 有效格式: 12345, a12345, z99999
❌ 无效格式: 1234, 123456, ab123, 12-34, A12345
```

#### 4. 应用处理器测试 (`handlers/application_test.go`)
测试申请管理功能：
- **申请提交**: 表单验证和数据存储
- **审批流程**: 批准/拒绝操作
- **IP 和端口验证**: 网络地址格式检查
- **权限控制**: 角色基础的访问控制

**IP 地址验证测试**:
```go
// 有效 IP
{"192.168.1.100", true},
{"10.0.0.1", true},
{"172.16.254.1", true},

// 无效 IP  
{"192.168.1.256", false},
{"192.168.1", false},
{"abc.def.ghi.jkl", false},
```

**端口验证测试**:
```go
// 有效端口
{80, true}, {443, true}, {8080, true}, {65535, true},

// 无效端口
{0, false}, {-1, false}, {65536, false},
```

#### 5. 集成测试 (`integration_test.go`)
测试端到端用户工作流：
- **完整注册流程**: 用户注册 → 登录 → 申请提交
- **审批工作流**: 申请创建 → 管理员审批 → 状态更新
- **多用户交互**: 不同角色用户的协作流程
- **中间件保护**: 认证和授权中间件验证

**完整工作流测试**:
1. 用户注册 (`POST /register`)
2. 用户登录 (`POST /login`) 
3. 提交申请 (`POST /apply`)
4. 管理员登录
5. 审批申请 (`POST /admin/approve` 或 `/admin/reject`)
6. 验证最终状态

### 测试工具 (`test_utils/test_helpers.go`)

提供测试辅助函数：
- `SetupTestDB()` - 初始化测试数据库
- `CreateTestUser()` - 创建测试用户
- `CreateTestApplication()` - 创建测试申请
- `ValidateUsernameFormat()` - 用户名格式验证
- `ValidateIPAddress()` / `ValidatePort()` - 网络地址验证

### 测试数据

#### 示例测试用户
```go
// 标准测试用户
{"12345", "password123", "applicant"},
{"67890", "password456", "applicant"}, 
{"a11111", "password789", "applicant"},
{"admin", "admin", "approver"},
```

#### 示例测试申请
```go
// 测试申请数据
{"192.168.1.100", 8080, "Development server", "pending"},
{"10.0.0.50", 22, "SSH access", "approved"},
{"172.16.0.10", 443, "HTTPS API", "rejected"},
```

### 测试环境配置

- **数据库**: 内存 SQLite (`:memory:`)
- **HTTP 测试**: `httptest` 包模拟请求
- **认证**: 真实的 bcrypt 哈希实现
- **隔离性**: 每个测试使用独立数据库状态
- **模板**: 测试环境使用虚拟模板

### 测试覆盖率

运行覆盖率测试：
```bash
# 生成覆盖率报告
make coverage

# 手动生成覆盖率
go test -coverprofile=coverage.out ./models ./database ./handlers
go tool cover -html=coverage.out -o coverage.html
```

### 性能测试

```bash
# 运行基准测试
make benchmark

# 手动运行基准测试
go test -bench=. ./models ./database ./handlers
```

### 测试最佳实践

1. **隔离性**: 每个测试独立运行，不依赖其他测试
2. **可重复性**: 测试结果稳定，多次运行结果一致
3. **覆盖性**: 覆盖正常流程和异常情况
4. **数据驱动**: 使用表驱动测试验证多种场景
5. **清理**: 测试后清理临时数据和资源

### 故障排除

#### 常见问题

**"database is locked"**
```bash
# 确保测试间正确清理数据库连接
# 使用独立的测试数据库
```

**"session not found"**  
```bash
# 为处理器测试模拟会话中间件
# 使用集成测试验证完整会话流程
```

**"template not found"**
```bash
# 确保模板目录存在
# 测试环境使用相对路径
```

**"permission denied (iptables)"**
```bash
# 预期行为 - 测试不执行实际的 iptables 命令
# 仅使用 sudo 进行手动应用测试
```

### 持续集成

项目设计支持 CI/CD 环境运行：

```bash
# CI 测试命令
go test -v -race ./...

# 带覆盖率的 CI 测试
go test -v -race -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html
```

## 部署

### 系统服务部署

创建 systemd 服务文件 `/etc/systemd/system/gatekeeper.service`:

```ini
[Unit]
Description=Gatekeeper IP Whitelist Management System
After=network.target

[Service]
Type=simple
User=gatekeeper
Group=gatekeeper
WorkingDirectory=/opt/gatekeeper
ExecStart=/opt/gatekeeper/gatekeeper_app -config=/etc/gatekeeper/config.json
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

启动服务：

```bash
sudo systemctl daemon-reload
sudo systemctl enable gatekeeper
sudo systemctl start gatekeeper
```

### Docker 部署

```dockerfile
FROM golang:1.23-alpine AS builder

WORKDIR /app
COPY . .
RUN go mod download
RUN go build -o gatekeeper_app

FROM alpine:latest
RUN apk --no-cache add ca-certificates iptables
WORKDIR /root/
COPY --from=builder /app/gatekeeper_app .
COPY --from=builder /app/templates ./templates
COPY --from=builder /app/static ./static

EXPOSE 58080
CMD ["./gatekeeper_app"]
```

### 反向代理配置 (Nginx)

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://localhost:58080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## 安全注意事项

### 🔒 生产环境安全设置

#### 1. 最小化权限
```bash
# 创建专用用户
sudo useradd -r -s /bin/false gatekeeper

# 配置 sudo 权限（仅限 iptables）
echo "gatekeeper ALL=(ALL) NOPASSWD: /usr/sbin/iptables" | sudo tee /etc/sudoers.d/gatekeeper
```

#### 2. 配置文件安全
```bash
# 设置配置文件权限
chmod 600 /etc/gatekeeper/config.json
chown gatekeeper:gatekeeper /etc/gatekeeper/config.json

# 数据库文件权限
chmod 600 /var/lib/gatekeeper/gatekeeper.db
chown gatekeeper:gatekeeper /var/lib/gatekeeper/gatekeeper.db
```

#### 3. 必须更改的默认设置

- ✅ **更改默认管理员密码**
- ✅ **设置强随机 Session 密钥** (推荐 64+ 字符)
- ✅ **提高密码加密强度** (`bcrypt_cost: 14` 或更高)
- ✅ **使用 HTTPS** (通过反向代理)
- ✅ **配置防火墙** (仅开放必要端口)

#### 4. 监控和日志
```bash
# 日志轮转配置
cat > /etc/logrotate.d/gatekeeper << EOF
/var/log/gatekeeper/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
EOF
```

## 贡献指南

欢迎贡献代码！请遵循以下步骤：

1. **Fork 项目**
2. **创建功能分支** (`git checkout -b feature/amazing-feature`)
3. **提交更改** (`git commit -m 'Add some amazing feature'`)
4. **推送到分支** (`git push origin feature/amazing-feature`)
5. **创建 Pull Request**

### 贡献要求

- 确保所有测试通过 (`make test`)
- 为新功能添加测试
- 遵循 Go 代码规范
- 更新相关文档

## 许可证

本项目采用 MIT 许可证。详情请参见 [LICENSE](LICENSE) 文件。

## 支持

如果您遇到问题或有疑问：

1. 查看 [Issues](../../issues) 中是否有相关问题
2. 查看项目文档和配置示例
3. 创建新的 Issue 并提供详细信息

## 更新日志

### v2.0.0 (Latest)
- ✨ 新增完整的配置系统
- 🔧 支持 JSON 配置文件
- 📝 改进文档和部署指南
- 🧪 完整的测试覆盖

### v1.0.0
- 🎉 初始版本
- ✅ 基本的 IP 白名单管理功能
- 👥 用户认证和角色管理
- 🔐 iptables 集成
