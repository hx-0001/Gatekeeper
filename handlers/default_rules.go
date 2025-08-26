package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"gatekeeper/database"
	"gatekeeper/logger"
	"gatekeeper/models"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

// Mutex to protect default rules operations from concurrent access
var defaultRulesMutex sync.Mutex

// DefaultRulesHandler handles the default rules management page
func DefaultRulesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		// Get current user information from session
		cfg := ensureConfig()
		session, _ := store.Get(r, cfg.Session.Name)
		username, ok := session.Values["username"].(string)
		if !ok {
			respondWithError(w, r, "未登录", http.StatusUnauthorized)
			return
		}

		role, ok := session.Values["role"].(string)
		if !ok {
			respondWithError(w, r, "用户角色信息缺失", http.StatusUnauthorized)
			return
		}

		// Get all default rules from database
		rules, err := database.GetAllDefaultRules()
		if err != nil {
			logger.Error("Failed to get all default rules in DefaultRulesHandler: %v", err)
			respondWithError(w, r, fmt.Sprintf("获取默认规则失败: %v", err), http.StatusInternalServerError)
			return
		}

		data := struct {
			Rules       []models.DefaultRule
			IsApprover  bool
			Username    string
		}{
			Rules:      rules,
			IsApprover: role == "approver",
			Username:   username,
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
			logger.Error("Failed to parse form data in AddDefaultRuleHandler: %v", err)
			respondWithError(w, r, "解析表单数据失败", http.StatusBadRequest)
			return
		}
	}

	// Validate and extract form data
	name := strings.TrimSpace(r.FormValue("name"))
	ipPattern := "" // 默认限制所有IP
	portStr := strings.TrimSpace(r.FormValue("port"))
	action := strings.TrimSpace(r.FormValue("action"))
	enabledStr := r.FormValue("enabled")
	approvalResponse := strings.TrimSpace(r.FormValue("approval_response"))

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
		ApprovalResponse: approvalResponse,
	}

	// Save to database
	logger.Info("Creating new default rule: name=%s, port=%d, action=%s, enabled=%t", rule.Name, rule.Port, rule.Action, rule.Enabled)
	ruleID, err := database.CreateDefaultRule(rule)
	if err != nil {
		logger.Error("Failed to create default rule in database: name=%s, port=%d, error=%v", rule.Name, rule.Port, err)
		respondWithError(w, r, fmt.Sprintf("创建默认规则失败: %v", err), http.StatusInternalServerError)
		return
	}

	// If rule is enabled, apply to iptables with duplicate cleanup
	if enabled {
		// First cleanup any existing duplicates
		cleanupDuplicateRules(ipPattern, strconv.Itoa(port), action)
		
		// Check if rule already exists to maintain idempotency
		exists, checkErr := checkIfRuleExists(ipPattern, strconv.Itoa(port), action)
		if checkErr == nil && !exists {
			err = applyDefaultRuleToIPTables(rule, "add")
			if err != nil {
				logger.Error("Failed to apply default rule to iptables: name=%s, port=%d, error=%v", rule.Name, rule.Port, err)
				// Delete the rule from database if iptables failed
				database.DeleteDefaultRule(int(ruleID))
				logger.Info("Cleaned up database rule after iptables failure: rule_id=%d", ruleID)
				respondWithError(w, r, fmt.Sprintf("应用iptables规则失败: %v", err), http.StatusInternalServerError)
				return
			}
		} else if checkErr != nil {
			// If we can't check, try to add anyway (existing behavior)
			err = applyDefaultRuleToIPTables(rule, "add")
			if err != nil {
				database.DeleteDefaultRule(int(ruleID))
				respondWithError(w, r, fmt.Sprintf("应用iptables规则失败: %v", err), http.StatusInternalServerError)
				return
			}
		}
		// If rule already exists, we don't need to add it again
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

	// Parse form data (handle both multipart and URL-encoded forms)
	err := r.ParseMultipartForm(32 << 20) // 32MB limit
	if err != nil {
		// Fallback to regular form parsing for URL-encoded forms
		err = r.ParseForm()
		if err != nil {
			respondWithError(w, r, "解析表单数据失败", http.StatusBadRequest)
			return
		}
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
	ipPattern := "" // 默认限制所有IP
	portStr := strings.TrimSpace(r.FormValue("port"))
	action := strings.TrimSpace(r.FormValue("action"))
	enabledStr := r.FormValue("enabled")
	approvalResponse := strings.TrimSpace(r.FormValue("approval_response"))

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
		ApprovalResponse: approvalResponse,
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
		// Rule was enabled - add to iptables with duplicate protection
		cleanupDuplicateRules(ipPattern, strconv.Itoa(port), action)
		
		exists, checkErr := checkIfRuleExists(ipPattern, strconv.Itoa(port), action)
		if checkErr == nil && !exists {
			err = applyDefaultRuleToIPTables(updatedRule, "add")
			if err != nil {
				respondWithError(w, r, fmt.Sprintf("应用iptables规则失败: %v", err), http.StatusInternalServerError)
				return
			}
		} else if checkErr != nil {
			// If we can't check, try to add anyway
			err = applyDefaultRuleToIPTables(updatedRule, "add")
			if err != nil {
				respondWithError(w, r, fmt.Sprintf("应用iptables规则失败: %v", err), http.StatusInternalServerError)
				return
			}
		}
		// If rule already exists, we don't need to add it again
	} else if oldRule.Enabled && enabled {
		// Rule was modified while enabled - update iptables with comprehensive cleanup
		if oldRule.Port != port || oldRule.IPPattern != ipPattern || oldRule.Action != action {
			// Remove all instances of old rule first
			err = applyDefaultRuleToIPTables(oldRule, "remove")
			if err != nil {
				respondWithError(w, r, fmt.Sprintf("移除旧iptables规则失败: %v", err), http.StatusInternalServerError)
				return
			}
			
			// Clean up any duplicates of the new rule that might exist
			cleanupDuplicateRules(ipPattern, strconv.Itoa(port), action)
			
			// Add the new rule
			err = applyDefaultRuleToIPTables(updatedRule, "add")
			if err != nil {
				// Try to restore old rule
				logger.Warn("Failed to add new rule, attempting to restore old rule: name=%s, port=%d", updatedRule.Name, updatedRule.Port)
				restoreErr := applyDefaultRuleToIPTables(oldRule, "add")
				if restoreErr != nil {
					logger.Error("Failed to restore old rule after update failure: name=%s, port=%d, error=%v", oldRule.Name, oldRule.Port, restoreErr)
				} else {
					logger.Info("Successfully restored old rule after update failure: name=%s, port=%d", oldRule.Name, oldRule.Port)
				}
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

	// Parse form data (handle both multipart and URL-encoded forms)
	err := r.ParseMultipartForm(32 << 20) // 32MB limit
	if err != nil {
		// Fallback to regular form parsing for URL-encoded forms
		err = r.ParseForm()
		if err != nil {
			respondWithError(w, r, "解析表单数据失败", http.StatusBadRequest)
			return
		}
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
// Note: This function should be called within mutex protection from the caller
func applyDefaultRuleToIPTables(rule models.DefaultRule, operation string) error {
	
	var action string
	switch operation {
	case "add":
		action = "-A" // Append for default rules (low priority)
	case "remove":
		action = "-D" // Delete
	default:
		return fmt.Errorf("invalid operation: %s", operation)
	}

	if operation == "remove" {
		// For removal, only remove one instance to avoid affecting other rules with same port
		return removeSingleMatchingRule(rule.IPPattern, strconv.Itoa(rule.Port), rule.Action)
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
// This function implements idempotent rule loading to prevent duplicates
func LoadDefaultRulesAtStartup() error {
	logger.Info("Starting default rules synchronization...")
	
	rules, err := database.GetEnabledDefaultRules()
	if err != nil {
		return fmt.Errorf("failed to get enabled default rules: %v", err)
	}

	// Step 1: Clean up any duplicate rules that may exist
	logger.Info("Cleaning up duplicate rules for %d enabled default rules...", len(rules))
	for _, rule := range rules {
		err = cleanupDuplicateRules(rule.IPPattern, strconv.Itoa(rule.Port), rule.Action)
		if err != nil {
			logger.Warn("Failed to cleanup duplicates for rule %s: %v", rule.Name, err)
		}
	}
	
	// Step 2: Check which rules are missing and add them
	logger.Info("Verifying and adding missing rules...")
	addedCount := 0
	for _, rule := range rules {
		exists, err := checkIfRuleExists(rule.IPPattern, strconv.Itoa(rule.Port), rule.Action)
		if err != nil {
			logger.Warn("Failed to check if rule exists for %s: %v", rule.Name, err)
			continue
		}
		
		if !exists {
			err = applyDefaultRuleToIPTables(rule, "add")
			if err != nil {
				logger.Warn("Failed to apply default rule %s: %v", rule.Name, err)
			} else {
				logger.Info("Added missing rule: %s (port %d)", rule.Name, rule.Port)
				addedCount++
			}
		} else {
			logger.Info("Rule already exists: %s (port %d)", rule.Name, rule.Port)
		}
	}

	logger.Info("Default rules synchronization complete: %d rules verified, %d added", len(rules), addedCount)
	return nil
}

// CheckIfRuleExists checks if a specific rule already exists in iptables (exported for testing)
func CheckIfRuleExists(ipPattern, port, action string) (bool, error) {
	return checkIfRuleExists(ipPattern, port, action)
}

// checkIfRuleExists checks if a specific rule already exists in iptables
func checkIfRuleExists(ipPattern, port, action string) (bool, error) {
	currentRules, err := getCurrentIPTablesRules()
	if err != nil {
		return false, err
	}
	
	targetPattern := fmt.Sprintf("tcp dpt:%s", port)
	actionUpper := strings.ToUpper(action)
	
	for _, rule := range currentRules {
		if strings.Contains(rule, targetPattern) && strings.Contains(rule, actionUpper) {
			// Further check IP pattern if specified
			if ipPattern != "" {
				if strings.Contains(rule, ipPattern) {
					return true, nil
				}
			} else {
				// No IP pattern specified, just check port and action
				return true, nil
			}
		}
	}
	
	return false, nil
}

// executeDefaultRuleIPTablesCommand is a specialized version for default rules
func executeDefaultRuleIPTablesCommand(action, ipAddress, port, ruleAction string) error {
	// Use the priority-aware iptables execution with "default" rule type
	return ExecuteIPTablesCommandWithPriority(action, ipAddress, port, ruleAction, "default")
}

// getRuleSignature generates a unique signature for an iptables rule
func getRuleSignature(ipPattern, port, action string) string {
	return fmt.Sprintf("%s:%s:%s", ipPattern, port, action)
}

// isGatekeeperRule checks if an iptables rule was created by Gatekeeper
// This helps avoid deleting rules created by other applications
func isGatekeeperRule(ruleText string) bool {
	// Check for patterns that indicate our rules:
	// 1. Rules with specific ports we manage (from database)
	// 2. Rules with ACCEPT action on TCP protocol
	// 3. Avoid system rules like loopback, established connections, etc.
	
	// Skip system rules
	if strings.Contains(ruleText, "lo ") || // loopback interface
		strings.Contains(ruleText, "ESTABLISHED") || // established connections
		strings.Contains(ruleText, "RELATED") || // related connections
		strings.Contains(ruleText, "state ") || // connection state rules
		strings.Contains(ruleText, "DROP ") && !strings.Contains(ruleText, "tcp dpt:") { // generic DROP rules
		return false
	}
	
	// Our rules pattern: tcp dpt:[port] and ACCEPT
	hasTcpDpt := strings.Contains(ruleText, "tcp dpt:")
	hasAcceptOrDrop := strings.Contains(ruleText, "ACCEPT") || strings.Contains(ruleText, "DROP")
	
	return hasTcpDpt && hasAcceptOrDrop
}

// getCurrentIPTablesRules gets current iptables rules that might be managed by Gatekeeper
func getCurrentIPTablesRules() ([]string, error) {
	cmd := exec.Command("sudo", "iptables", "-L", "INPUT", "-n", "--line-numbers")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	
	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("failed to get iptables rules: %v", err)
	}
	
	lines := strings.Split(stdout.String(), "\n")
	var rules []string
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Chain") || strings.HasPrefix(line, "target") {
			continue
		}
		
		// Only consider rules that might be managed by Gatekeeper
		if isGatekeeperRule(line) {
			rules = append(rules, line)
		}
	}
	
	return rules, nil
}

// CleanupDuplicateRules removes duplicate iptables rules for a specific rule configuration (exported for testing)
func CleanupDuplicateRules(ipPattern, port, action string) error {
	return cleanupDuplicateRules(ipPattern, port, action)
}

// cleanupDuplicateRules removes duplicate iptables rules for a specific rule configuration
// This function is conservative and only removes rules that exactly match our patterns
func cleanupDuplicateRules(ipPattern, port, action string) error {
	// Get all current rules
	currentRules, err := getCurrentIPTablesRules()
	if err != nil {
		return fmt.Errorf("failed to get current rules: %v", err)
	}
	
	// Find rules matching our pattern
	var matchingLines []int
	targetPattern := fmt.Sprintf("tcp dpt:%s", port)
	
	for _, rule := range currentRules {
		// Check if this rule matches our target
		if strings.Contains(rule, targetPattern) && strings.Contains(rule, strings.ToUpper(action)) {
			// Extract line number (first field)
			parts := strings.Fields(rule)
			if len(parts) > 0 {
				if lineNum, err := strconv.Atoi(parts[0]); err == nil {
					matchingLines = append(matchingLines, lineNum)
				}
			}
		}
	}
	
	// If we have more than one matching rule, remove the extras
	// Keep the first rule and remove the duplicates (in reverse order to maintain line numbers)
	if len(matchingLines) > 1 {
		logger.Info("Found %d duplicate rules for port %s, cleaning up...", len(matchingLines), port)
		
		// Remove duplicates in reverse order to maintain line numbers
		for i := len(matchingLines) - 1; i > 0; i-- {
			lineNum := matchingLines[i]
			err := removeIPTablesRuleByLineNumber(lineNum)
			if err != nil {
				logger.Warn("Failed to remove duplicate rule at line %d: %v", lineNum, err)
			} else {
				logger.Info("Removed duplicate rule at line %d for port %s", lineNum, port)
			}
		}
	}
	
	return nil
}

// removeIPTablesRuleByLineNumber removes an iptables rule by its line number
func removeIPTablesRuleByLineNumber(lineNumber int) error {
	cmd := exec.Command("sudo", "iptables", "-D", "INPUT", strconv.Itoa(lineNumber))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("iptables delete error: %s, details: %s", err, stderr.String())
	}
	return nil
}

// removeSingleMatchingRule removes only one instance of an iptables rule that matches the given pattern
// This prevents accidentally removing other rules with the same port
func removeSingleMatchingRule(ipPattern, port, action string) error {
	// Use the standard iptables -D command which removes only the first match
	return executeDefaultRuleIPTablesCommand("-D", ipPattern, port, action)
}

// removeAllMatchingRules removes all iptables rules that match the given pattern
// This is more thorough than single -D command which only removes the first match
// Note: This function should only be used for cleanup operations, not for deleting specific rules
func removeAllMatchingRules(ipPattern, port, action string) error {
	maxAttempts := 10 // Prevent infinite loops
	
	for attempt := 0; attempt < maxAttempts; attempt++ {
		// Try to remove one instance of the rule
		err := executeDefaultRuleIPTablesCommand("-D", ipPattern, port, action)
		if err != nil {
			// If removal fails, it likely means no more matching rules exist
			if attempt == 0 {
				// If the first attempt fails, it might be a real error
				return err
			}
			// If subsequent attempts fail, it's likely because no more rules exist
			break
		}
		logger.Info("Removed matching rule (attempt %d) for %s:%s %s", attempt+1, ipPattern, port, action)
	}
	
	return nil
}

// SyncDefaultRulesWithIPTables synchronizes database state with actual iptables rules
// This function can be called periodically or on-demand to fix inconsistencies
func SyncDefaultRulesWithIPTables() error {
	defaultRulesMutex.Lock()
	defer defaultRulesMutex.Unlock()
	
	fmt.Println("Starting default rules synchronization with iptables...")
	
	// Get all rules from database
	allRules, err := database.GetAllDefaultRules()
	if err != nil {
		return fmt.Errorf("failed to get all default rules: %v", err)
	}
	
	syncedCount := 0
	fixedCount := 0
	
	for _, rule := range allRules {
		exists, err := checkIfRuleExists(rule.IPPattern, strconv.Itoa(rule.Port), rule.Action)
		if err != nil {
			logger.Warn("Failed to check rule existence for %s: %v", rule.Name, err)
			continue
		}
		
		if rule.Enabled && !exists {
			// Rule should exist but doesn't - add it
			err = executeDefaultRuleIPTablesCommand("-A", rule.IPPattern, strconv.Itoa(rule.Port), rule.Action)
			if err != nil {
				logger.Warn("Failed to add missing rule %s: %v", rule.Name, err)
			} else {
				logger.Info("Fixed: Added missing rule %s (port %d)", rule.Name, rule.Port)
				fixedCount++
			}
		} else if !rule.Enabled && exists {
			// Rule should not exist but does - remove it
			err = removeAllMatchingRules(rule.IPPattern, strconv.Itoa(rule.Port), rule.Action)
			if err != nil {
				logger.Warn("Failed to remove unexpected rule %s: %v", rule.Name, err)
			} else {
				logger.Info("Fixed: Removed unexpected rule %s (port %d)", rule.Name, rule.Port)
				fixedCount++
			}
		} else {
			// Rule state is consistent
			syncedCount++
		}
		
		// Clean up any duplicates for this rule
		cleanupDuplicateRules(rule.IPPattern, strconv.Itoa(rule.Port), rule.Action)
	}
	
	logger.Info("Synchronization complete: %d rules in sync, %d fixed", syncedCount, fixedCount)
	return nil
}