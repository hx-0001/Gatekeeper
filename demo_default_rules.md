# 默认规则功能演示

## 功能概述

新实现的默认规则功能允许管理员配置全局的防火墙规则，这些规则会自动应用到系统中。规则优先级如下：

1. **最高优先级**: 审批通过的规则（使用 `iptables -I` 插入到最前面）
2. **低优先级**: 默认规则（使用 `iptables -A` 追加到后面）

## 新增功能

### 1. 数据库表
- 新增 `default_rules` 表，用于存储全局默认规则

### 2. 管理界面
- `/admin/default-rules` - 默认规则管理页面
- 支持添加、编辑、删除、启用/禁用规则

### 3. API接口
- `GET /api/default-rules` - 获取所有默认规则的JSON数据

### 4. iptables优先级支持
- 修改了 `executeIPTablesCommand` 函数以支持规则优先级
- 审批规则使用 `-I INPUT 1` (高优先级)
- 默认规则使用 `-A INPUT` (低优先级)

## 使用场景示例

### 场景：内网代理服务器安全配置

**背景**: 部署了Claude Code代理服务，需要默认封禁部分端口，然后通过审批放通特定IP的白名单。

**配置步骤**:

1. **设置默认规则**（管理员配置）:
   ```
   规则名称: 禁止SSH
   IP模式: [空] (所有IP)
   端口: 22
   动作: DROP
   状态: 启用
   描述: 默认禁止所有SSH访问
   ```

2. **设置默认规则**:
   ```
   规则名称: 禁止RDP
   IP模式: [空]
   端口: 3389
   动作: DROP
   状态: 启用
   描述: 默认禁止所有RDP访问
   ```

3. **用户申请特例**:
   - 用户申请访问: IP=192.168.1.100, 端口=22
   - 管理员审批通过

4. **最终iptables规则效果**:
   ```bash
   # 高优先级：审批通过的规则 (在前面)
   iptables -I INPUT 1 -s 192.168.1.100 -p tcp --dport 22 -j ACCEPT
   
   # 低优先级：默认规则 (在后面)
   iptables -A INPUT -p tcp --dport 22 -j DROP
   iptables -A INPUT -p tcp --dport 3389 -j DROP
   ```

**结果**: 192.168.1.100可以访问SSH，其他IP被默认规则阻止。

## 技术实现要点

### 1. 数据模型
```go
type DefaultRule struct {
    ID          int
    Name        string
    IPPattern   string    // IP模式：具体IP、CIDR、或空(所有IP)
    Port        int
    Action      string    // "ACCEPT" 或 "DROP"
    Enabled     bool
    Description string
    CreatedAt   time.Time
    UpdatedAt   time.Time
}
```

### 2. 规则优先级逻辑
```go
func ExecuteIPTablesCommandWithPriority(action, ipAddress, port, ruleAction, ruleType string) error {
    if ruleType == "approved" {
        // 高优先级：插入到最前面
        if action == "-A" {
            args = append(args, "-I", "INPUT", "1")
        }
    } else {
        // 低优先级：追加到后面
        args = append(args, action, "INPUT")
    }
    // ... 构建完整命令
}
```

### 3. 启动时加载默认规则
```go
func LoadDefaultRulesAtStartup() error {
    rules, err := database.GetEnabledDefaultRules()
    for _, rule := range rules {
        applyDefaultRuleToIPTables(rule, "add")
    }
}
```

## 安全考虑

1. **权限控制**: 只有 `approver` 角色可以管理默认规则
2. **规则验证**: 严格验证端口范围、IP格式、动作类型
3. **优先级设计**: 确保审批规则始终优先于默认规则
4. **错误处理**: iptables执行失败时回滚数据库操作

## 测试覆盖

- ✅ 数据模型验证测试
- ✅ 数据库CRUD操作测试
- ✅ HTTP处理器测试
- ✅ iptables优先级逻辑测试
- ✅ 完整集成测试

## 使用说明

1. 以管理员身份登录系统
2. 点击导航栏的"默认规则"
3. 在表单中填写规则信息并提交
4. 规则会立即应用到iptables（如果启用）
5. 可以随时编辑、禁用或删除规则

## 总结

这个实现完全满足了您的需求：
- ✅ 管理员可以配置全局拦截规则
- ✅ 全局规则优先级低于审批规则
- ✅ 简单的两层优先级系统
- ✅ 完整的Web管理界面
- ✅ 符合现有代码风格和架构