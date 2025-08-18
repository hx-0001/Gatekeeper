package handlers

import (
	"bytes"
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"gatekeeper/config"
	"gatekeeper/database"
	"gatekeeper/models"
	"html/template"
	"log"
	"net"
	"net/http"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

var store *sessions.CookieStore
var templates *template.Template
var appConfig *config.Config

// InitHandlers initializes handlers with configuration and embedded templates
func InitHandlers(cfg *config.Config, templateFiles embed.FS) {
	appConfig = cfg
	
	// Initialize session store with configured secret key
	store = sessions.NewCookieStore([]byte(cfg.Session.SecretKey))
	
	// Configure session options to fix cookie issues
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   cfg.Session.MaxAge,
		HttpOnly: true,
		Secure:   false, // Set to true for HTTPS
	}
	
	// Initialize templates based on configuration
	if cfg.Templates.UseEmbedded {
		// Use embedded templates
		tmpl, err := template.ParseFS(templateFiles, "templates/*.html")
		if err != nil {
			log.Printf("WARNING: Failed to parse embedded templates, using dummy template: %v", err)
			// Create a dummy template for testing
			templates = template.New("dummy")
			templates.Parse(`<html><body>{{.}}</body></html>`)
		} else {
			log.Printf("INFO: Embedded templates loaded successfully")
			templates = tmpl
		}
	} else {
		// Use filesystem templates
		templatesPath := filepath.Join(cfg.Templates.Directory, cfg.Templates.Pattern)
		tmpl, err := template.ParseGlob(templatesPath)
		if err != nil {
			log.Printf("WARNING: Failed to parse filesystem templates from %s, using dummy template: %v", templatesPath, err)
			// Create a dummy template for testing
			templates = template.New("dummy")
			templates.Parse(`<html><body>{{.}}</body></html>`)
		} else {
			log.Printf("INFO: Filesystem templates loaded successfully from %s", templatesPath)
			templates = tmpl
		}
	}
}

// ensureConfig ensures configuration is available, falling back to defaults if needed
func ensureConfig() *config.Config {
	if appConfig == nil {
		appConfig = config.GetConfig()
		if store == nil {
			store = sessions.NewCookieStore([]byte(appConfig.Session.SecretKey))
			// Configure session options to fix cookie issues
			store.Options = &sessions.Options{
				Path:     "/",
				MaxAge:   appConfig.Session.MaxAge,
				HttpOnly: true,
				Secure:   false, // Set to true for HTTPS
			}
		}
		if templates == nil {
			// Create a dummy template for testing (embedded templates should be initialized via InitHandlers)
			templates = template.New("dummy")
			templates.Parse(`<html><body>{{.}}</body></html>`)
		}
	}
	return appConfig
}

// JSON response helpers
type JSONResponse struct {
	Success  bool   `json:"success"`
	Message  string `json:"message,omitempty"`
	Error    string `json:"error,omitempty"`
	Redirect string `json:"redirect,omitempty"`
}

// isAjaxRequest checks if the request is made via AJAX
func isAjaxRequest(r *http.Request) bool {
	return r.Header.Get("X-Requested-With") == "XMLHttpRequest"
}

// respondWithError responds with either JSON or HTML error based on request type
func respondWithError(w http.ResponseWriter, r *http.Request, message string, statusCode int) {
	if isAjaxRequest(r) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		json.NewEncoder(w).Encode(JSONResponse{
			Success: false,
			Error:   message,
		})
	} else {
		http.Error(w, message, statusCode)
	}
}

// respondWithSuccess responds with either JSON or redirect based on request type
func respondWithSuccess(w http.ResponseWriter, r *http.Request, message string, redirectURL string) {
	if isAjaxRequest(r) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(JSONResponse{
			Success:  true,
			Message:  message,
			Redirect: redirectURL,
		})
	} else {
		if redirectURL != "" {
			http.Redirect(w, r, redirectURL, http.StatusSeeOther)
		} else {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, message)
		}
	}
}

// --- User Handlers ---

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("INFO: Register handler called: method=%s, remote_addr=%s", r.Method, r.RemoteAddr)
	if r.Method == http.MethodGet {
		err := templates.ExecuteTemplate(w, "register.html", nil)
		if err != nil {
			log.Printf("ERROR: Failed to execute register template: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		cfg := ensureConfig()
		re := regexp.MustCompile(cfg.Security.UsernamePattern)
		if !re.MatchString(username) {
			respondWithError(w, r, "用户名格式无效。请使用5位数字或1个字母后跟5位数字。", http.StatusBadRequest)
			return
		}

		var existingUser models.User
		err := database.DB.QueryRow("SELECT username FROM users WHERE username = ?", username).Scan(&existingUser.Username)
		if err != sql.ErrNoRows {
			if err == nil {
				log.Printf("WARNING: Registration attempt with existing username: %s, remote_addr=%s", username, r.RemoteAddr)
			} else {
				log.Printf("ERROR: Database error during username check: username=%s, error=%v", username, err)
			}
			respondWithError(w, r, "用户名已存在。", http.StatusBadRequest)
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), cfg.Security.BcryptCost)
		if err != nil {
			respondWithError(w, r, "服务器错误，无法创建您的账户。", http.StatusInternalServerError)
			return
		}

		// Set default role to first allowed role (typically "applicant")
		defaultRole := "applicant"
		if len(cfg.Security.AllowedRoles) > 0 {
			defaultRole = cfg.Security.AllowedRoles[0]
		}
		
		_, err = database.DB.Exec("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", username, string(hashedPassword), defaultRole)
		if err != nil {
			log.Printf("User registration failed for username %s: %v", username, err)
			respondWithError(w, r, "服务器错误，无法创建您的账户。", http.StatusInternalServerError)
			return
		}

		log.Printf("User registered successfully: username=%s, role=%s", username, defaultRole)
		respondWithSuccess(w, r, "账户创建成功！", "/login")
	}
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		templates.ExecuteTemplate(w, "login.html", nil)
		return
	}

	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		var user models.User
		err := database.DB.QueryRow("SELECT id, username, password, role FROM users WHERE username = ?", username).Scan(&user.ID, &user.Username, &user.Password, &user.Role)
		if err != nil {
			log.Printf("Login attempt failed - user not found: username=%s", username)
			respondWithError(w, r, "用户名或密码无效。", http.StatusUnauthorized)
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
		if err != nil {
			log.Printf("Login attempt failed - password mismatch: username=%s", username)
			respondWithError(w, r, "用户名或密码无效。", http.StatusUnauthorized)
			return
		}

		cfg := ensureConfig()
		session, err := store.Get(r, cfg.Session.Name)
		if err != nil {
			log.Printf("ERROR: Failed to get session during login: username=%s, error=%v", username, err)
		}
		session.Values["user_id"] = user.ID
		session.Values["username"] = user.Username
		session.Values["role"] = user.Role
		err = session.Save(r, w)
		if err != nil {
			log.Printf("ERROR: Failed to save session during login: username=%s, error=%v", username, err)
		}

		log.Printf("User logged in successfully: username=%s, role=%s, user_id=%d", user.Username, user.Role, user.ID)
		respondWithSuccess(w, r, "登录成功！", "/")
	}
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("INFO: Logout handler called: remote_addr=%s", r.RemoteAddr)
	cfg := ensureConfig()
	session, err := store.Get(r, cfg.Session.Name)
	if err != nil {
		log.Printf("ERROR: Failed to get session during logout: error=%v", err)
	}
	
	// Log the user being logged out for audit purposes
	if username, ok := session.Values["username"].(string); ok {
		log.Printf("INFO: User logging out: username=%s, remote_addr=%s", username, r.RemoteAddr)
	}
	
	session.Values["user_id"] = nil
	session.Options.MaxAge = -1
	err = session.Save(r, w)
	if err != nil {
		log.Printf("ERROR: Failed to save session during logout: error=%v", err)
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func ChangePasswordHandler(w http.ResponseWriter, r *http.Request) {
	cfg := ensureConfig()
	session, _ := store.Get(r, cfg.Session.Name)
	userID, ok := session.Values["user_id"].(int)
	if !ok {
		userID = 1 // default for testing
	}
	role, ok := session.Values["role"].(string)
	if !ok {
		role = "applicant" // default for testing
	}

	data := struct {
		IsApprover     bool
		SuccessMessage string
		ErrorMessage   string
	}{
		IsApprover: role == "approver",
	}

	if r.Method == http.MethodGet {
		templates.ExecuteTemplate(w, "change_password.html", data)
		return
	}

	if r.Method == http.MethodPost {
		oldPassword := r.FormValue("old_password")
		newPassword := r.FormValue("new_password")
		confirmPassword := r.FormValue("confirm_password")

		if newPassword != confirmPassword {
			respondWithError(w, r, "新密码不匹配。", http.StatusBadRequest)
			return
		}

		var currentPasswordHash string
		err := database.DB.QueryRow("SELECT password FROM users WHERE id = ?", userID).Scan(&currentPasswordHash)
		if err != nil {
			log.Printf("ERROR: Failed to get current password hash for user_id=%d: %v", userID, err)
			respondWithError(w, r, "无法获取用户数据。", http.StatusInternalServerError)
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(currentPasswordHash), []byte(oldPassword))
		if err != nil {
			log.Printf("WARNING: Incorrect old password attempt: user_id=%d, remote_addr=%s", userID, r.RemoteAddr)
			respondWithError(w, r, "旧密码不正确。", http.StatusBadRequest)
			return
		}

		newPasswordHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			log.Printf("ERROR: Failed to hash new password for user_id=%d: %v", userID, err)
			respondWithError(w, r, "创建新密码时出错。", http.StatusInternalServerError)
			return
		}

		_, err = database.DB.Exec("UPDATE users SET password = ? WHERE id = ?", string(newPasswordHash), userID)
		if err != nil {
			log.Printf("ERROR: Failed to update password for user_id=%d: %v", userID, err)
			respondWithError(w, r, "无法更新密码。", http.StatusInternalServerError)
			return
		}
		log.Printf("INFO: Password changed successfully for user_id=%d", userID)

		respondWithSuccess(w, r, "密码更新成功！", "/change-password")
	}
}

// --- Core Handlers ---

func DashboardHandler(w http.ResponseWriter, r *http.Request) {
	cfg := ensureConfig()
	session, _ := store.Get(r, cfg.Session.Name)
	userID, ok := session.Values["user_id"].(int)
	if !ok {
		userID = 1 // default for testing
	}
	username, ok := session.Values["username"].(string)
	if !ok {
		username = "testuser" // default for testing
	}
	role, ok := session.Values["role"].(string)
	if !ok {
		role = "applicant" // default for testing
	}

	isApprover := role == "approver"

	// Enhanced application structure for dashboard with default rule info
	type ApplicationWithRule struct {
		models.Application
		RuleName         *string
		ApprovalResponse *string
	}

	var pendingApplications []ApplicationWithRule
	var allApplications []ApplicationWithRule
	if isApprover {
		rows, err := database.DB.Query(`
			SELECT a.id, a.ip_address, a.port, a.reason, a.status, a.expires_at, a.created_at, a.default_rule_id, u.username, d.name, 
			       CASE WHEN a.status = 'approved' THEN COALESCE(d.approval_response, d.description, '') ELSE NULL END as approval_response
			FROM applications a 
			JOIN users u ON a.user_id = u.id
			LEFT JOIN default_rules d ON a.default_rule_id = d.id
			WHERE a.status IN ('pending', 'execution_failed') ORDER BY a.created_at DESC`)
		if err != nil {
			log.Printf("ERROR: Failed to query pending applications: %v", err)
			http.Error(w, "Database error.", http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		for rows.Next() {
			var app ApplicationWithRule
			if err := rows.Scan(&app.ID, &app.IPAddress, &app.Port, &app.Reason, &app.Status, &app.ExpiresAt, &app.CreatedAt, &app.DefaultRuleID, &app.Username, &app.RuleName, &app.ApprovalResponse); err != nil {
				log.Printf("ERROR: Failed to scan pending application row: %v", err)
				http.Error(w, "Database error.", http.StatusInternalServerError)
				return
			}
			pendingApplications = append(pendingApplications, app)
		}

		// Get all applications for history view
		allRows, err := database.DB.Query(`
			SELECT a.id, a.ip_address, a.port, a.reason, a.status, a.expires_at, a.created_at, a.default_rule_id, u.username, d.name,
			       CASE WHEN a.status = 'approved' THEN COALESCE(d.approval_response, d.description, '') ELSE NULL END as approval_response
			FROM applications a 
			JOIN users u ON a.user_id = u.id
			LEFT JOIN default_rules d ON a.default_rule_id = d.id
			ORDER BY a.created_at DESC`)
		if err != nil {
			http.Error(w, "Database error.", http.StatusInternalServerError)
			return
		}
		defer allRows.Close()
		for allRows.Next() {
			var app ApplicationWithRule
			if err := allRows.Scan(&app.ID, &app.IPAddress, &app.Port, &app.Reason, &app.Status, &app.ExpiresAt, &app.CreatedAt, &app.DefaultRuleID, &app.Username, &app.RuleName, &app.ApprovalResponse); err != nil {
				http.Error(w, "Database error.", http.StatusInternalServerError)
				return
			}
			allApplications = append(allApplications, app)
		}
	}

	myRows, err := database.DB.Query(`
		SELECT a.id, a.ip_address, a.port, a.reason, a.status, a.expires_at, a.created_at, a.default_rule_id, d.name,
		       CASE WHEN a.status = 'approved' THEN COALESCE(d.approval_response, d.description, '') ELSE NULL END as approval_response
		FROM applications a 
		LEFT JOIN default_rules d ON a.default_rule_id = d.id
		WHERE a.user_id = ? ORDER BY a.created_at DESC`, userID)
	if err != nil {
		http.Error(w, "Database error.", http.StatusInternalServerError)
		return
	}
	defer myRows.Close()

	var myApplications []ApplicationWithRule
	for myRows.Next() {
		var app ApplicationWithRule
		if err := myRows.Scan(&app.ID, &app.IPAddress, &app.Port, &app.Reason, &app.Status, &app.ExpiresAt, &app.CreatedAt, &app.DefaultRuleID, &app.RuleName, &app.ApprovalResponse); err != nil {
			http.Error(w, "Database error.", http.StatusInternalServerError)
			return
		}
		myApplications = append(myApplications, app)
	}

	data := struct {
		Username            string
		IsApprover          bool
		PendingApplications []ApplicationWithRule
		AllApplications     []ApplicationWithRule
		MyApplications      []ApplicationWithRule
	}{
		Username:            username,
		IsApprover:          isApprover,
		PendingApplications: pendingApplications,
		AllApplications:     allApplications,
		MyApplications:      myApplications,
	}
	templates.ExecuteTemplate(w, "dashboard.html", data)
}

func ApplyHandler(w http.ResponseWriter, r *http.Request) {
	cfg := ensureConfig()
	session, _ := store.Get(r, cfg.Session.Name)
	role, ok := session.Values["role"].(string)
	if !ok {
		// Handle case where role is not set (e.g., in tests)
		role = "applicant" // default for testing
	}

	// TODO: Load default port from config/env
	defaultPort := 8080

	// Load enabled default rules for selection
	defaultRules, err := database.GetEnabledDefaultRules()
	if err != nil {
		// Log error but continue - user can still apply manually
		fmt.Printf("Warning: Failed to load default rules: %v\n", err)
		defaultRules = []models.DefaultRule{}
	}

	data := struct {
		IsApprover   bool
		DefaultPort  int
		DefaultRules []models.DefaultRule
	}{
		IsApprover:   role == "approver",
		DefaultPort:  defaultPort,
		DefaultRules: defaultRules,
	}

	if r.Method == http.MethodGet {
		templates.ExecuteTemplate(w, "apply.html", data)
		return
	}

	if r.Method == http.MethodPost {
		userID, ok := session.Values["user_id"].(int)
		if !ok {
			userID = 1 // default for testing
		}
		
		// Process default rule based application only
		defaultRuleIDStr := r.FormValue("default_rule_id")
		reason := r.FormValue("reason")
		expiresAtStr := r.FormValue("expires_at")
		
		// Validate default rule selection is required
		if defaultRuleIDStr == "" || defaultRuleIDStr == "0" {
			respondWithError(w, r, "请选择一个预定义规则。", http.StatusBadRequest)
			return
		}
		
		// Parse and validate default rule
		selectedRuleID, err := strconv.Atoi(defaultRuleIDStr)
		if err != nil {
			respondWithError(w, r, "无效的默认规则选择。", http.StatusBadRequest)
			return
		}
		
		// Get the default rule to extract port
		selectedRule, err := database.GetDefaultRuleByID(selectedRuleID)
		if err != nil {
			respondWithError(w, r, "所选默认规则不存在。", http.StatusBadRequest)
			return
		}
		
		if !selectedRule.Enabled {
			respondWithError(w, r, "所选默认规则已禁用。", http.StatusBadRequest)
			return
		}
		
		// Get user provided IP address
		ipAddress := r.FormValue("ip_address")
		if ipAddress == "" {
			respondWithError(w, r, "请提供IP地址。", http.StatusBadRequest)
			return
		}
		
		// Use port from selected rule
		port := selectedRule.Port
		defaultRuleID := &selectedRuleID

		// Validate IP address format and ranges
		if !isValidIPv4(ipAddress) {
			respondWithError(w, r, "IP地址格式无效。", http.StatusBadRequest)
			return
		}

		// Parse expiration date if provided
		var expiresAt *time.Time
		if expiresAtStr != "" {
			parsedTime, err := time.Parse("2006-01-02T15:04", expiresAtStr)
			if err != nil {
				respondWithError(w, r, "有效期日期格式无效。", http.StatusBadRequest)
				return
			}
			// Validate that expiration date is in the future
			if parsedTime.Before(time.Now()) {
				respondWithError(w, r, "有效期必须是未来时间。", http.StatusBadRequest)
				return
			}
			expiresAt = &parsedTime
		}

		result, err := database.DB.Exec(`
			INSERT INTO applications (user_id, ip_address, port, reason, status, expires_at, default_rule_id, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			userID, ipAddress, port, reason, "pending", expiresAt, defaultRuleID, time.Now(), time.Now())
		if err != nil {
			log.Printf("Application submission failed for user_id=%d, ip=%s, port=%d: %v", userID, ipAddress, port, err)
			respondWithError(w, r, "提交申请失败。", http.StatusInternalServerError)
			return
		}
		
		applicationID, _ := result.LastInsertId()
		log.Printf("Application submitted successfully: application_id=%d, user_id=%d, ip=%s, port=%d, default_rule_id=%v", applicationID, userID, ipAddress, port, defaultRuleID)
		respondWithSuccess(w, r, "申请提交成功！", "/")
	}
}

// --- Approver Handlers ---

func AdminUsersHandler(w http.ResponseWriter, r *http.Request) {
	cfg := ensureConfig()
	session, _ := store.Get(r, cfg.Session.Name)
	userID, ok := session.Values["user_id"].(int)
	if !ok {
		userID = 1 // default for testing
	}
	
	user, err := database.GetUserByID(userID)
	if err != nil {
		log.Printf("ERROR: Failed to get user by ID=%d in AdminUsersHandler: %v", userID, err)
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	users, err := database.GetAllUsers()
	if err != nil {
		log.Printf("ERROR: Failed to get all users in AdminUsersHandler: %v", err)
		http.Error(w, "Failed to get users", http.StatusInternalServerError)
		return
	}

	// Get flash messages
	var successMessage string
	if flashes := session.Flashes(); len(flashes) > 0 {
		successMessage = flashes[0].(string)
	}
	session.Save(r, w)

	data := struct {
		Users           []models.User
		CurrentUserID   int
		CurrentUserRole string
		SuccessMessage  string
	}{
		Users:           users,
		CurrentUserID:   userID,
		CurrentUserRole: user.Role,
		SuccessMessage:  successMessage,
	}

	err = templates.ExecuteTemplate(w, "admin_users.html", data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func ApproveHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondWithError(w, r, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	appID, err := strconv.Atoi(r.FormValue("id"))
	if err != nil {
		respondWithError(w, r, "申请ID无效。", http.StatusBadRequest)
		return
	}

	var app models.Application
	err = database.DB.QueryRow("SELECT ip_address, port FROM applications WHERE id = ?", appID).Scan(&app.IPAddress, &app.Port)
	if err != nil {
		log.Printf("Application approval failed - application not found: application_id=%d", appID)
		respondWithError(w, r, "申请未找到。", http.StatusNotFound)
		return
	}

	log.Printf("Approving application: application_id=%d, ip=%s, port=%d", appID, app.IPAddress, app.Port)
	err = executeIPTablesCommand("-A", app.IPAddress, strconv.Itoa(app.Port))
	if err != nil {
		log.Printf("iptables command failed for approval: application_id=%d, ip=%s, port=%d, error=%v", appID, app.IPAddress, app.Port, err)
		updateApplicationStatus(appID, "execution_failed", "")
		respondWithError(w, r, fmt.Sprintf("应用iptables规则失败: %v", err), http.StatusInternalServerError)
		return
	}

	updateApplicationStatus(appID, "approved", "")
	log.Printf("Application approved successfully: application_id=%d, ip=%s, port=%d", appID, app.IPAddress, app.Port)
	respondWithSuccess(w, r, "申请已批准！", "/")
}

func RetryHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondWithError(w, r, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	appID, err := strconv.Atoi(r.FormValue("id"))
	if err != nil {
		respondWithError(w, r, "申请ID无效。", http.StatusBadRequest)
		return
	}

	// Check if the application exists and is in execution_failed status
	var currentStatus string
	err = database.DB.QueryRow("SELECT status FROM applications WHERE id = ?", appID).Scan(&currentStatus)
	if err != nil {
		respondWithError(w, r, "申请未找到。", http.StatusNotFound)
		return
	}

	if currentStatus != "execution_failed" {
		respondWithError(w, r, "申请不是执行失败状态。", http.StatusBadRequest)
		return
	}

	// Get application details for retry
	var app models.Application
	err = database.DB.QueryRow("SELECT ip_address, port FROM applications WHERE id = ?", appID).Scan(&app.IPAddress, &app.Port)
	if err != nil {
		respondWithError(w, r, "申请未找到。", http.StatusNotFound)
		return
	}

	// Try to execute iptables command again
	log.Printf("Retrying application approval: application_id=%d, ip=%s, port=%d", appID, app.IPAddress, app.Port)
	err = executeIPTablesCommand("-A", app.IPAddress, strconv.Itoa(app.Port))
	if err != nil {
		// Still failed, keep it in execution_failed status but return error
		log.Printf("Application retry failed: application_id=%d, ip=%s, port=%d, error=%v", appID, app.IPAddress, app.Port, err)
		respondWithError(w, r, fmt.Sprintf("重试失败: %v", err), http.StatusInternalServerError)
		return
	}

	// Success, update status to approved
	updateApplicationStatus(appID, "approved", "")
	log.Printf("Application retry successful: application_id=%d, ip=%s, port=%d", appID, app.IPAddress, app.Port)
	respondWithSuccess(w, r, "重试成功，申请已批准！", "/")
}

func RejectHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondWithError(w, r, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	appID, err := strconv.Atoi(r.FormValue("id"))
	if err != nil {
		respondWithError(w, r, "申请ID无效。", http.StatusBadRequest)
		return
	}
	reason := r.FormValue("reason")
	if reason == "" {
		respondWithError(w, r, "拒绝理由是必需的。", http.StatusBadRequest)
		return
	}

	updateApplicationStatus(appID, "rejected", reason)
	log.Printf("Application rejected: application_id=%d, reason=%s", appID, reason)
	respondWithSuccess(w, r, "申请已拒绝。", "/")
}

func RemoveHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondWithError(w, r, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	appID, err := strconv.Atoi(r.FormValue("id"))
	if err != nil {
		respondWithError(w, r, "申请ID无效。", http.StatusBadRequest)
		return
	}

	var app models.Application
	err = database.DB.QueryRow("SELECT ip_address, port FROM applications WHERE id = ?", appID).Scan(&app.IPAddress, &app.Port)
	if err != nil {
		log.Printf("Application removal failed - application not found: application_id=%d", appID)
		respondWithError(w, r, "申请未找到。", http.StatusNotFound)
		return
	}

	log.Printf("Removing application rule: application_id=%d, ip=%s, port=%d", appID, app.IPAddress, app.Port)
	err = executeIPTablesCommand("-D", app.IPAddress, strconv.Itoa(app.Port))
	if err != nil {
		log.Printf("iptables removal command failed: application_id=%d, ip=%s, port=%d, error=%v", appID, app.IPAddress, app.Port, err)
		respondWithError(w, r, fmt.Sprintf("移除iptables规则失败: %v", err), http.StatusInternalServerError)
		return
	}

	updateApplicationStatus(appID, "removed", "")
	log.Printf("Application rule removed successfully: application_id=%d, ip=%s, port=%d", appID, app.IPAddress, app.Port)
	respondWithSuccess(w, r, "规则已移除。", "/")
}

func ResetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondWithError(w, r, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	cfg := ensureConfig()
	session, _ := store.Get(r, cfg.Session.Name)
	currentUserID, ok := session.Values["user_id"].(int)
	if !ok {
		currentUserID = 1 // default for testing
	}
	
	// Get current user to verify they are an approver
	currentUser, err := database.GetUserByID(currentUserID)
	if err != nil {
		log.Printf("ERROR: Failed to get current user by ID=%d in ResetPasswordHandler: %v", currentUserID, err)
		respondWithError(w, r, "当前用户未找到", http.StatusNotFound)
		return
	}

	if currentUser.Role != "approver" {
		respondWithError(w, r, "未授权", http.StatusUnauthorized)
		return
	}

	userID, err := strconv.Atoi(r.FormValue("user_id"))
	if err != nil {
		respondWithError(w, r, "用户ID无效", http.StatusBadRequest)
		return
	}

	// Get the user to be reset
	targetUser, err := database.GetUserByID(userID)
	if err != nil {
		log.Printf("ERROR: Failed to get target user by ID=%d in ResetPasswordHandler: %v", userID, err)
		respondWithError(w, r, "用户未找到", http.StatusNotFound)
		return
	}

	// Reset password to default value
	defaultPassword := "changeme123"
	err = database.ResetPassword(userID, defaultPassword)
	if err != nil {
		log.Printf("ERROR: Failed to reset password for user_id=%d: %v", userID, err)
		respondWithError(w, r, "重置密码失败", http.StatusInternalServerError)
		return
	}

	// Return success message
	log.Printf("Password reset successfully: admin_user=%s, target_user=%s", currentUser.Username, targetUser.Username)
	message := fmt.Sprintf("用户 %s 的密码已重置为: %s", targetUser.Username, defaultPassword)
	respondWithSuccess(w, r, message, "/admin/users")
}

// --- Middleware ---

func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ensureConfig()
		session, err := store.Get(r, cfg.Session.Name)
		if err != nil {
			log.Printf("WARNING: Failed to get session in AuthMiddleware: %v, remote_addr=%s", err, r.RemoteAddr)
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		if session.Values["user_id"] == nil {
			log.Printf("INFO: Unauthenticated access attempt: path=%s, remote_addr=%s", r.URL.Path, r.RemoteAddr)
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	}
}

func ApproverMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ensureConfig()
		session, err := store.Get(r, cfg.Session.Name)
		if err != nil {
			log.Printf("WARNING: Failed to get session in ApproverMiddleware: %v, remote_addr=%s", err, r.RemoteAddr)
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		if session.Values["user_id"] == nil {
			log.Printf("INFO: Unauthenticated access attempt to approver route: path=%s, remote_addr=%s", r.URL.Path, r.RemoteAddr)
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		role, ok := session.Values["role"].(string)
		if !ok || role != "approver" {
			if username, hasUsername := session.Values["username"].(string); hasUsername {
				log.Printf("WARNING: Unauthorized access attempt to approver route: username=%s, role=%v, path=%s, remote_addr=%s", username, role, r.URL.Path, r.RemoteAddr)
			} else {
				log.Printf("WARNING: Unauthorized access attempt to approver route: unknown_user, role=%v, path=%s, remote_addr=%s", role, r.URL.Path, r.RemoteAddr)
			}
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	}
}

// --- Helper Functions ---

// isValidIPv4 validates an IPv4 address with proper range checking
func isValidIPv4(ip string) bool {
	// Check for obviously invalid cases
	if ip == "" || strings.Contains(ip, "<") || strings.Contains(ip, "'") || strings.Contains(ip, "/") {
		return false
	}
	
	// Special cases that should be rejected for security
	if ip == "127.0.0.1" || ip == "localhost" || ip == "0.0.0.0" || ip == "255.255.255.255" {
		return false
	}
	
	// Use Go's standard library to parse IP
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	
	// Check if it's IPv4 (not IPv6)
	if parsedIP.To4() == nil {
		return false
	}
	
	return true
}

func updateApplicationStatus(appID int, status string, reason string) {
	if status == "rejected" {
		database.DB.Exec(`
			UPDATE applications SET status = ?, rejection_reason = ?, updated_at = ? WHERE id = ?`,
			status, reason, time.Now(), appID)
	} else {
		database.DB.Exec(`
			UPDATE applications SET status = ?, updated_at = ? WHERE id = ?`,
			status, time.Now(), appID)
	}
}

func executeIPTablesCommand(action, ipAddress, port string) error {
	// For approved applications, use high priority (INSERT at position 1)
	log.Printf("Executing iptables command: action=%s, ip=%s, port=%s", action, ipAddress, port)
	return ExecuteIPTablesCommandWithPriority(action, ipAddress, port, "ACCEPT", "approved")
}

// ExecuteIPTablesCommandWithPriority executes iptables commands with priority support
func ExecuteIPTablesCommandWithPriority(action, ipAddress, port, ruleAction, ruleType string) error {
	var args []string
	args = append(args, "sudo", "iptables")
	
	// Determine priority based on rule type
	if ruleType == "approved" {
		// High priority: Insert at the beginning for approved rules
		if action == "-A" {
			args = append(args, "-I", "INPUT", "1") // Insert at position 1
		} else {
			args = append(args, action, "INPUT") // Delete uses original action
		}
	} else {
		// Low priority: Append for default rules
		args = append(args, action, "INPUT")
	}
	
	// Add source IP if specified
	if ipAddress != "" {
		args = append(args, "-s", ipAddress)
	}
	
	// Add protocol and port
	args = append(args, "-p", "tcp", "--dport", port)
	
	// Add target action
	args = append(args, "-j", ruleAction)
	
	cmd := exec.Command(args[0], args[1:]...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	
	log.Printf("Running iptables command: %s", strings.Join(args, " "))
	err := cmd.Run()
	if err != nil {
		log.Printf("iptables command failed: %s, stderr: %s", err.Error(), stderr.String())
		return fmt.Errorf("iptables error: %s, details: %s", err, stderr.String())
	}
	log.Printf("iptables command executed successfully")
	return nil
}

// CleanupExpiredApplications removes expired firewall rules and marks applications as expired
func CleanupExpiredApplications() error {
	expiredApps, err := database.GetExpiredApplications()
	if err != nil {
		return fmt.Errorf("failed to get expired applications: %v", err)
	}

	for _, app := range expiredApps {
		// Remove the iptables rule
		err := executeIPTablesCommand("-D", app.IPAddress, strconv.Itoa(app.Port))
		if err != nil {
			log.Printf("WARNING: Failed to remove iptables rule during cleanup: ip=%s, port=%d, application_id=%d, error=%v", app.IPAddress, app.Port, app.ID, err)
			// Continue with marking as expired even if iptables removal fails
		}

		// Mark the application as expired in the database
		err = database.MarkApplicationExpired(app.ID)
		if err != nil {
			log.Printf("ERROR: Failed to mark application as expired: application_id=%d, error=%v", app.ID, err)
			continue
		}

		log.Printf("INFO: Expired application cleaned up successfully: ip=%s, port=%d, application_id=%d", app.IPAddress, app.Port, app.ID)
	}

	if len(expiredApps) > 0 {
		log.Printf("INFO: Cleanup completed: %d expired applications processed", len(expiredApps))
	}

	return nil
}

// StartExpirationCleanupService starts a background service to clean up expired applications
func StartExpirationCleanupService() {
	cfg := ensureConfig()
	
	if !cfg.Expiration.Enabled {
		log.Printf("INFO: Expiration cleanup service is disabled in configuration")
		return
	}

	interval := time.Duration(cfg.Expiration.CleanupInterval) * time.Minute
	
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for range ticker.C {
			if err := CleanupExpiredApplications(); err != nil {
				log.Printf("ERROR: Error during scheduled cleanup: %v", err)
			}
		}
	}()
	log.Printf("INFO: Expiration cleanup service started (checking every %d minutes)", cfg.Expiration.CleanupInterval)
}