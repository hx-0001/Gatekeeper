package handlers

import (
	"encoding/json"
	"fmt"
	"gatekeeper/database"
	"gatekeeper/models"
	"net/http"
	"strconv"
	"strings"
)

// DefaultRulesHandler handles the default rules management page
func DefaultRulesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		// Get all default rules from database
		rules, err := database.GetAllDefaultRules()
		if err != nil {
			respondWithError(w, r, fmt.Sprintf("获取默认规则失败: %v", err), http.StatusInternalServerError)
			return
		}

		data := struct {
			Rules []models.DefaultRule
		}{
			Rules: rules,
		}

		templates.ExecuteTemplate(w, "default_rules.html", data)
	}
}

// AddDefaultRuleHandler handles adding a new default rule
func AddDefaultRuleHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse form data (support both application/x-www-form-urlencoded and multipart/form-data)
	err := r.ParseMultipartForm(32 << 20) // 32 MB max memory
	if err != nil {
		// Fallback to regular form parsing for non-multipart forms
		err = r.ParseForm()
		if err != nil {
			respondWithError(w, r, "解析表单数据失败", http.StatusBadRequest)
			return
		}
	}

	// Validate and extract form data
	name := strings.TrimSpace(r.FormValue("name"))
	ipPattern := strings.TrimSpace(r.FormValue("ip_pattern"))
	portStr := strings.TrimSpace(r.FormValue("port"))
	action := strings.TrimSpace(r.FormValue("action"))
	enabledStr := r.FormValue("enabled")
	description := strings.TrimSpace(r.FormValue("description"))

	// Validate required fields
	if name == "" {
		respondWithError(w, r, "规则名称不能为空", http.StatusBadRequest)
		return
	}

	if portStr == "" {
		respondWithError(w, r, "端口号不能为空", http.StatusBadRequest)
		return
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		respondWithError(w, r, "端口号必须是1-65535之间的数字", http.StatusBadRequest)
		return
	}

	if action != "ACCEPT" && action != "DROP" {
		respondWithError(w, r, "动作必须是ACCEPT或DROP", http.StatusBadRequest)
		return
	}

	enabled := enabledStr == "true" || enabledStr == "on"

	// Create default rule
	rule := models.DefaultRule{
		Name:        name,
		IPPattern:   ipPattern,
		Port:        port,
		Action:      action,
		Enabled:     enabled,
		Description: description,
	}

	// Save to database
	ruleID, err := database.CreateDefaultRule(rule)
	if err != nil {
		respondWithError(w, r, fmt.Sprintf("创建默认规则失败: %v", err), http.StatusInternalServerError)
		return
	}

	// If rule is enabled, apply to iptables
	if enabled {
		err = applyDefaultRuleToIPTables(rule, "add")
		if err != nil {
			// Delete the rule from database if iptables failed
			database.DeleteDefaultRule(int(ruleID))
			respondWithError(w, r, fmt.Sprintf("应用iptables规则失败: %v", err), http.StatusInternalServerError)
			return
		}
	}

	// Redirect back to default rules page
	http.Redirect(w, r, "/admin/default-rules", http.StatusSeeOther)
}

// UpdateDefaultRuleHandler handles updating an existing default rule
func UpdateDefaultRuleHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse form data
	err := r.ParseForm()
	if err != nil {
		respondWithError(w, r, "解析表单数据失败", http.StatusBadRequest)
		return
	}

	// Get rule ID
	idStr := strings.TrimSpace(r.FormValue("id"))
	if idStr == "" {
		respondWithError(w, r, "规则ID不能为空", http.StatusBadRequest)
		return
	}

	id, err := strconv.Atoi(idStr)
	if err != nil {
		respondWithError(w, r, "无效的规则ID", http.StatusBadRequest)
		return
	}

	// Get existing rule
	oldRule, err := database.GetDefaultRuleByID(id)
	if err != nil {
		respondWithError(w, r, "规则不存在", http.StatusNotFound)
		return
	}

	// Validate and extract form data
	name := strings.TrimSpace(r.FormValue("name"))
	ipPattern := strings.TrimSpace(r.FormValue("ip_pattern"))
	portStr := strings.TrimSpace(r.FormValue("port"))
	action := strings.TrimSpace(r.FormValue("action"))
	enabledStr := r.FormValue("enabled")
	description := strings.TrimSpace(r.FormValue("description"))

	// Validate required fields
	if name == "" {
		respondWithError(w, r, "规则名称不能为空", http.StatusBadRequest)
		return
	}

	if portStr == "" {
		respondWithError(w, r, "端口号不能为空", http.StatusBadRequest)
		return
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		respondWithError(w, r, "端口号必须是1-65535之间的数字", http.StatusBadRequest)
		return
	}

	if action != "ACCEPT" && action != "DROP" {
		respondWithError(w, r, "动作必须是ACCEPT或DROP", http.StatusBadRequest)
		return
	}

	enabled := enabledStr == "true" || enabledStr == "on"

	// Create updated rule
	updatedRule := models.DefaultRule{
		ID:          id,
		Name:        name,
		IPPattern:   ipPattern,
		Port:        port,
		Action:      action,
		Enabled:     enabled,
		Description: description,
	}

	// Handle iptables changes
	if oldRule.Enabled && !enabled {
		// Rule was disabled - remove from iptables
		err = applyDefaultRuleToIPTables(oldRule, "remove")
		if err != nil {
			respondWithError(w, r, fmt.Sprintf("移除iptables规则失败: %v", err), http.StatusInternalServerError)
			return
		}
	} else if !oldRule.Enabled && enabled {
		// Rule was enabled - add to iptables
		err = applyDefaultRuleToIPTables(updatedRule, "add")
		if err != nil {
			respondWithError(w, r, fmt.Sprintf("应用iptables规则失败: %v", err), http.StatusInternalServerError)
			return
		}
	} else if oldRule.Enabled && enabled {
		// Rule was modified while enabled - update iptables
		if oldRule.Port != port || oldRule.IPPattern != ipPattern || oldRule.Action != action {
			// Remove old rule and add new one
			err = applyDefaultRuleToIPTables(oldRule, "remove")
			if err != nil {
				respondWithError(w, r, fmt.Sprintf("移除旧iptables规则失败: %v", err), http.StatusInternalServerError)
				return
			}
			err = applyDefaultRuleToIPTables(updatedRule, "add")
			if err != nil {
				// Try to restore old rule
				applyDefaultRuleToIPTables(oldRule, "add")
				respondWithError(w, r, fmt.Sprintf("应用新iptables规则失败: %v", err), http.StatusInternalServerError)
				return
			}
		}
	}

	// Update in database
	err = database.UpdateDefaultRule(updatedRule)
	if err != nil {
		respondWithError(w, r, fmt.Sprintf("更新默认规则失败: %v", err), http.StatusInternalServerError)
		return
	}

	// Redirect back to default rules page
	http.Redirect(w, r, "/admin/default-rules", http.StatusSeeOther)
}

// DeleteDefaultRuleHandler handles deleting a default rule
func DeleteDefaultRuleHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse form data
	err := r.ParseForm()
	if err != nil {
		respondWithError(w, r, "解析表单数据失败", http.StatusBadRequest)
		return
	}

	// Get rule ID
	idStr := strings.TrimSpace(r.FormValue("id"))
	if idStr == "" {
		respondWithError(w, r, "规则ID不能为空", http.StatusBadRequest)
		return
	}

	id, err := strconv.Atoi(idStr)
	if err != nil {
		respondWithError(w, r, "无效的规则ID", http.StatusBadRequest)
		return
	}

	// Get existing rule
	rule, err := database.GetDefaultRuleByID(id)
	if err != nil {
		respondWithError(w, r, "规则不存在", http.StatusNotFound)
		return
	}

	// Remove from iptables if enabled
	if rule.Enabled {
		err = applyDefaultRuleToIPTables(rule, "remove")
		if err != nil {
			respondWithError(w, r, fmt.Sprintf("移除iptables规则失败: %v", err), http.StatusInternalServerError)
			return
		}
	}

	// Delete from database
	err = database.DeleteDefaultRule(id)
	if err != nil {
		// Try to restore iptables rule if database deletion failed
		if rule.Enabled {
			applyDefaultRuleToIPTables(rule, "add")
		}
		respondWithError(w, r, fmt.Sprintf("删除默认规则失败: %v", err), http.StatusInternalServerError)
		return
	}

	// Redirect back to default rules page
	http.Redirect(w, r, "/admin/default-rules", http.StatusSeeOther)
}

// DefaultRulesAPIHandler handles API requests for default rules
func DefaultRulesAPIHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		// Get all default rules
		rules, err := database.GetAllDefaultRules()
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to get default rules: %v", err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(rules)
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// applyDefaultRuleToIPTables applies or removes a default rule to/from iptables
func applyDefaultRuleToIPTables(rule models.DefaultRule, operation string) error {
	var action string
	if operation == "add" {
		action = "-A" // Append for default rules (low priority)
	} else if operation == "remove" {
		action = "-D" // Delete
	} else {
		return fmt.Errorf("invalid operation: %s", operation)
	}

	// Build iptables command arguments
	var args []string
	args = append(args, "sudo", "iptables", action, "INPUT")

	// Add source IP pattern if specified
	if rule.IPPattern != "" {
		args = append(args, "-s", rule.IPPattern)
	}

	// Add protocol and port
	args = append(args, "-p", "tcp", "--dport", strconv.Itoa(rule.Port))

	// Add action (ACCEPT or DROP)
	args = append(args, "-j", rule.Action)

	// Execute iptables command
	return executeDefaultRuleIPTablesCommand(action, rule.IPPattern, strconv.Itoa(rule.Port), rule.Action)
}

// LoadDefaultRulesAtStartup loads and applies all enabled default rules at application startup
func LoadDefaultRulesAtStartup() error {
	rules, err := database.GetEnabledDefaultRules()
	if err != nil {
		return fmt.Errorf("failed to get enabled default rules: %v", err)
	}

	for _, rule := range rules {
		err = applyDefaultRuleToIPTables(rule, "add")
		if err != nil {
			// Log error but continue with other rules
			fmt.Printf("Warning: Failed to apply default rule %s: %v\n", rule.Name, err)
		}
	}

	fmt.Printf("Loaded %d default rules\n", len(rules))
	return nil
}

// executeDefaultRuleIPTablesCommand is a specialized version for default rules
func executeDefaultRuleIPTablesCommand(action, ipAddress, port, ruleAction string) error {
	// Use the priority-aware iptables execution with "default" rule type
	return ExecuteIPTablesCommandWithPriority(action, ipAddress, port, ruleAction, "default")
}