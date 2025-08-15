package handlers

import (
	"bytes"
	"database/sql"
	"fmt"
	"gatekeeper/database"
	"gatekeeper/models"
	"html/template"
	"net/http"
	"os/exec"
	"regexp"
	"strconv"
	"time"

	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

var store = sessions.NewCookieStore([]byte("something-very-secret"))
var templates = template.Must(template.ParseGlob("templates/*.html"))

// --- User Handlers ---

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		templates.ExecuteTemplate(w, "register.html", nil)
		return
	}

	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		re := regexp.MustCompile(`^([a-zA-Z]\d{5}|\d{5})$`)
		if !re.MatchString(username) {
			http.Error(w, "Invalid username format. Use 5 digits or 1 letter followed by 5 digits.", http.StatusBadRequest)
			return
		}

		var existingUser models.User
		err := database.DB.QueryRow("SELECT username FROM users WHERE username = ?", username).Scan(&existingUser.Username)
		if err != sql.ErrNoRows {
			http.Error(w, "Username already exists.", http.StatusBadRequest)
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Server error, unable to create your account.", http.StatusInternalServerError)
			return
		}

		_, err = database.DB.Exec("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", username, string(hashedPassword), "applicant")
		if err != nil {
			http.Error(w, "Server error, unable to create your account.", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/login", http.StatusSeeOther)
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
			http.Error(w, "Invalid username or password.", http.StatusUnauthorized)
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
		if err != nil {
			http.Error(w, "Invalid username or password.", http.StatusUnauthorized)
			return
		}

		session, _ := store.Get(r, "session-name")
		session.Values["user_id"] = user.ID
		session.Values["username"] = user.Username
		session.Values["role"] = user.Role
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")
	session.Values["user_id"] = nil
	session.Options.MaxAge = -1
	session.Save(r, w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func ChangePasswordHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")
	userID := session.Values["user_id"].(int)
	role := session.Values["role"].(string)

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
			data.ErrorMessage = "New passwords do not match."
			templates.ExecuteTemplate(w, "change_password.html", data)
			return
		}

		var currentPasswordHash string
		err := database.DB.QueryRow("SELECT password FROM users WHERE id = ?", userID).Scan(&currentPasswordHash)
		if err != nil {
			data.ErrorMessage = "Could not retrieve user data."
			templates.ExecuteTemplate(w, "change_password.html", data)
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(currentPasswordHash), []byte(oldPassword))
		if err != nil {
			data.ErrorMessage = "Incorrect old password."
			templates.ExecuteTemplate(w, "change_password.html", data)
			return
		}

		newPasswordHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			data.ErrorMessage = "Error creating new password."
			templates.ExecuteTemplate(w, "change_password.html", data)
			return
		}

		_, err = database.DB.Exec("UPDATE users SET password = ? WHERE id = ?", string(newPasswordHash), userID)
		if err != nil {
			data.ErrorMessage = "Could not update password."
			templates.ExecuteTemplate(w, "change_password.html", data)
			return
		}

		data.SuccessMessage = "Password updated successfully!"
		templates.ExecuteTemplate(w, "change_password.html", data)
	}
}

// --- Core Handlers ---

func DashboardHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")
	userID := session.Values["user_id"].(int)
	username := session.Values["username"].(string)
	role := session.Values["role"].(string)

	isApprover := role == "approver"

	var pendingApplications []models.Application
	if isApprover {
		rows, err := database.DB.Query(`
			SELECT a.id, a.ip_address, a.port, a.reason, a.created_at, u.username
			FROM applications a JOIN users u ON a.user_id = u.id
			WHERE a.status = 'pending' ORDER BY a.created_at DESC`)
		if err != nil {
			http.Error(w, "Database error.", http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		for rows.Next() {
			var app models.Application
			if err := rows.Scan(&app.ID, &app.IPAddress, &app.Port, &app.Reason, &app.CreatedAt, &app.Username); err != nil {
				http.Error(w, "Database error.", http.StatusInternalServerError)
				return
			}
			pendingApplications = append(pendingApplications, app)
		}
	}

	myRows, err := database.DB.Query(`
		SELECT id, ip_address, port, reason, status, created_at
		FROM applications WHERE user_id = ? ORDER BY created_at DESC`, userID)
	if err != nil {
		http.Error(w, "Database error.", http.StatusInternalServerError)
		return
	}
	defer myRows.Close()

	var myApplications []models.Application
	for myRows.Next() {
		var app models.Application
		if err := myRows.Scan(&app.ID, &app.IPAddress, &app.Port, &app.Reason, &app.Status, &app.CreatedAt); err != nil {
			http.Error(w, "Database error.", http.StatusInternalServerError)
			return
		}
		myApplications = append(myApplications, app)
	}

	data := struct {
		Username            string
		IsApprover          bool
		PendingApplications []models.Application
		MyApplications      []models.Application
	}{
		Username:            username,
		IsApprover:          isApprover,
		PendingApplications: pendingApplications,
		MyApplications:      myApplications,
	}
	templates.ExecuteTemplate(w, "dashboard.html", data)
}

func ApplyHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")
	role := session.Values["role"].(string)

	// TODO: Load default port from config/env
	defaultPort := 8080

	data := struct {
		IsApprover  bool
		DefaultPort int
	}{
		IsApprover:  role == "approver",
		DefaultPort: defaultPort,
	}

	if r.Method == http.MethodGet {
		templates.ExecuteTemplate(w, "apply.html", data)
		return
	}

	if r.Method == http.MethodPost {
		userID := session.Values["user_id"].(int)
		ipAddress := r.FormValue("ip_address")
		portStr := r.FormValue("port")
		reason := r.FormValue("reason")

		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			http.Error(w, "Invalid port number.", http.StatusBadRequest)
			return
		}

		re := regexp.MustCompile(`^([0-9]{1,3}\.){3}[0-9]{1,3}$`)
		if !re.MatchString(ipAddress) {
			http.Error(w, "Invalid IP address format.", http.StatusBadRequest)
			return
		}

		_, err = database.DB.Exec(`
			INSERT INTO applications (user_id, ip_address, port, reason, status, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			userID, ipAddress, port, reason, "pending", time.Now(), time.Now())
		if err != nil {
			http.Error(w, "Failed to submit application.", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

// --- Approver Handlers ---

func AdminUsersHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")
	userID := session.Values["user_id"].(int)
	
	user, err := database.GetUserByID(userID)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	users, err := database.GetAllUsers()
	if err != nil {
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

	tmpl, err := template.ParseFiles("templates/admin_users.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	tmpl.Execute(w, data)
}

func ApproveHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	appID, err := strconv.Atoi(r.FormValue("id"))
	if err != nil {
		http.Error(w, "Invalid application ID.", http.StatusBadRequest)
		return
	}

	var app models.Application
	err = database.DB.QueryRow("SELECT ip_address, port FROM applications WHERE id = ?", appID).Scan(&app.IPAddress, &app.Port)
	if err != nil {
		http.Error(w, "Application not found.", http.StatusNotFound)
		return
	}

	err = executeIPTablesCommand("-A", app.IPAddress, strconv.Itoa(app.Port))
	if err != nil {
		updateApplicationStatus(appID, "execution_failed", "")
		http.Error(w, fmt.Sprintf("Failed to apply iptables rule: %v", err), http.StatusInternalServerError)
		return
	}

	updateApplicationStatus(appID, "approved", "")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func RejectHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	appID, err := strconv.Atoi(r.FormValue("id"))
	if err != nil {
		http.Error(w, "Invalid application ID.", http.StatusBadRequest)
		return
	}
	reason := r.FormValue("reason")
	if reason == "" {
		http.Error(w, "Rejection reason is required.", http.StatusBadRequest)
		return
	}

	updateApplicationStatus(appID, "rejected", reason)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func RemoveHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	appID, err := strconv.Atoi(r.FormValue("id"))
	if err != nil {
		http.Error(w, "Invalid application ID.", http.StatusBadRequest)
		return
	}

	var app models.Application
	err = database.DB.QueryRow("SELECT ip_address, port FROM applications WHERE id = ?", appID).Scan(&app.IPAddress, &app.Port)
	if err != nil {
		http.Error(w, "Application not found.", http.StatusNotFound)
		return
	}

	err = executeIPTablesCommand("-D", app.IPAddress, strconv.Itoa(app.Port))
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to remove iptables rule: %v", err), http.StatusInternalServerError)
		return
	}

	updateApplicationStatus(appID, "removed", "")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func ResetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	session, _ := store.Get(r, "session-name")
	currentUserID := session.Values["user_id"].(int)
	
	// Get current user to verify they are an approver
	currentUser, err := database.GetUserByID(currentUserID)
	if err != nil {
		http.Error(w, "Current user not found", http.StatusNotFound)
		return
	}

	if currentUser.Role != "approver" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	userID, err := strconv.Atoi(r.FormValue("user_id"))
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	// Get the user to be reset
	targetUser, err := database.GetUserByID(userID)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Reset password to default value
	defaultPassword := "changeme123"
	err = database.ResetPassword(userID, defaultPassword)
	if err != nil {
		http.Error(w, "Failed to reset password", http.StatusInternalServerError)
		return
	}

	// Set success message and redirect back to admin users page
	session, _ = store.Get(r, "session-name")
	session.AddFlash(fmt.Sprintf("用户 %s 的密码已重置为: %s", targetUser.Username, defaultPassword))
	session.Save(r, w)

	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

// --- Middleware ---

func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, "session-name")
		if err != nil || session.Values["user_id"] == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	}
}

func ApproverMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, "session-name")
		if err != nil || session.Values["user_id"] == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		role, ok := session.Values["role"].(string)
		if !ok || role != "approver" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	}
}

// --- Helper Functions ---

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
	cmd := exec.Command("sudo", "iptables", action, "INPUT", "-s", ipAddress, "-p", "tcp", "--dport", port, "-j", "ACCEPT")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("iptables error: %s, details: %s", err, stderr.String())
	}
	return nil
}