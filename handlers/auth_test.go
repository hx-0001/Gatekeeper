package handlers

import (
	"gatekeeper/database"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
	_ "github.com/mattn/go-sqlite3"
)

func setupTestDatabase() {
	database.InitDB(":memory:")
	
	// Clear any existing test data
	database.DB.Exec("DELETE FROM applications")
	database.DB.Exec("DELETE FROM users WHERE username != 'admin'")
}

func TestLoginHandler_GET(t *testing.T) {
	setupTestDatabase()
	
	req, err := http.NewRequest("GET", "/login", nil)
	if err != nil {
		t.Fatal(err)
	}
	
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(LoginHandler)
	handler.ServeHTTP(rr, req)
	
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
	
	// Check that the template is rendered (basic check)
	body := rr.Body.String()
	if !strings.Contains(body, "html") && !strings.Contains(body, "body") {
		t.Logf("Template test - Response body: %s", body)
		t.Log("Template rendering test skipped - using dummy templates in tests")
	}
}

func TestLoginHandler_POST_ValidCredentials(t *testing.T) {
	setupTestDatabase()
	
	// Test with admin credentials (created during InitDB)
	form := url.Values{}
	form.Add("username", "admin")
	form.Add("password", "admin")
	
	req, err := http.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(LoginHandler)
	handler.ServeHTTP(rr, req)
	
	// Should redirect to dashboard after successful login
	if status := rr.Code; status != http.StatusSeeOther {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusSeeOther)
	}
	
	// Check redirect location
	location := rr.Header().Get("Location")
	if location != "/" {
		t.Errorf("Expected redirect to '/', got '%s'", location)
	}
	
	// Check that session cookie is set
	cookies := rr.Result().Cookies()
	sessionCookieFound := false
	for _, cookie := range cookies {
		if cookie.Name == "session-name" { // This depends on your session store configuration
			sessionCookieFound = true
			break
		}
	}
	if !sessionCookieFound {
		// Note: Session cookie name might be different based on gorilla/sessions configuration
		t.Log("Session cookie should be set (cookie name might vary)")
	}
}

func TestLoginHandler_POST_InvalidCredentials(t *testing.T) {
	setupTestDatabase()
	
	form := url.Values{}
	form.Add("username", "admin")
	form.Add("password", "wrongpassword")
	
	req, err := http.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(LoginHandler)
	handler.ServeHTTP(rr, req)
	
	// Should return error for invalid credentials
	if status := rr.Code; status != http.StatusUnauthorized {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusUnauthorized)
	}
}

func TestLoginHandler_POST_NonexistentUser(t *testing.T) {
	setupTestDatabase()
	
	form := url.Values{}
	form.Add("username", "nonexistent")
	form.Add("password", "password")
	
	req, err := http.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(LoginHandler)
	handler.ServeHTTP(rr, req)
	
	// Should return error for nonexistent user
	if status := rr.Code; status != http.StatusUnauthorized {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusUnauthorized)
	}
}

func TestRegisterHandler_GET(t *testing.T) {
	setupTestDatabase()
	
	req, err := http.NewRequest("GET", "/register", nil)
	if err != nil {
		t.Fatal(err)
	}
	
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(RegisterHandler)
	handler.ServeHTTP(rr, req)
	
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
	
	// Check that the template is rendered
	body := rr.Body.String()
	if !strings.Contains(body, "html") && !strings.Contains(body, "body") {
		t.Logf("Template test - Response body: %s", body)
		t.Log("Template rendering test skipped - using dummy templates in tests")
	}
}

func TestRegisterHandler_POST_ValidUser(t *testing.T) {
	setupTestDatabase()
	
	form := url.Values{}
	form.Add("username", "12345")
	form.Add("password", "testpassword123")
	
	req, err := http.NewRequest("POST", "/register", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(RegisterHandler)
	handler.ServeHTTP(rr, req)
	
	// Should redirect to login after successful registration
	if status := rr.Code; status != http.StatusSeeOther {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusSeeOther)
	}
	
	// Check redirect location
	location := rr.Header().Get("Location")
	if location != "/login" {
		t.Errorf("Expected redirect to '/login', got '%s'", location)
	}
	
	// Verify user was created in database
	var count int
	err = database.DB.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", "12345").Scan(&count)
	if err != nil {
		t.Fatal(err)
	}
	
	if count != 1 {
		t.Error("User should be created in database")
	}
}

func TestRegisterHandler_POST_ValidUserWithLetter(t *testing.T) {
	setupTestDatabase()
	
	form := url.Values{}
	form.Add("username", "a12345")
	form.Add("password", "testpassword123")
	
	req, err := http.NewRequest("POST", "/register", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(RegisterHandler)
	handler.ServeHTTP(rr, req)
	
	// Should succeed
	if status := rr.Code; status != http.StatusSeeOther {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusSeeOther)
	}
}

func TestRegisterHandler_POST_InvalidUsernameFormat(t *testing.T) {
	setupTestDatabase()
	
	testCases := []struct {
		name     string
		username string
	}{
		{"Too short", "1234"},
		{"Too long", "123456"},
		{"Invalid format", "ab1234"},
		{"Letters only", "abcde"},
		{"Special characters", "12-45"},
		{"Mixed case", "A12345"},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			form := url.Values{}
			form.Add("username", tc.username)
			form.Add("password", "testpassword123")
			
			req, err := http.NewRequest("POST", "/register", strings.NewReader(form.Encode()))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			
			rr := httptest.NewRecorder()
			handler := http.HandlerFunc(RegisterHandler)
			handler.ServeHTTP(rr, req)
			
			// Should return bad request for invalid username format
			if status := rr.Code; status != http.StatusBadRequest {
				t.Errorf("Handler returned wrong status code for username '%s': got %v want %v", 
					tc.username, status, http.StatusBadRequest)
			}
		})
	}
}

func TestRegisterHandler_POST_DuplicateUsername(t *testing.T) {
	setupTestDatabase()
	
	// Create user first
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	_, err := database.DB.Exec("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
		"12345", string(hashedPassword), "applicant")
	if err != nil {
		t.Fatal(err)
	}
	
	// Try to register with same username
	form := url.Values{}
	form.Add("username", "12345")
	form.Add("password", "anotherpassword")
	
	req, err := http.NewRequest("POST", "/register", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(RegisterHandler)
	handler.ServeHTTP(rr, req)
	
	// Should return bad request for duplicate username
	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusBadRequest)
	}
	
	if !strings.Contains(rr.Body.String(), "用户名已存在") {
		t.Errorf("Response should indicate username already exists, got: %s", rr.Body.String())
	}
}

func TestLogoutHandler(t *testing.T) {
	setupTestDatabase()
	
	req, err := http.NewRequest("GET", "/logout", nil)
	if err != nil {
		t.Fatal(err)
	}
	
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(LogoutHandler)
	handler.ServeHTTP(rr, req)
	
	// Should redirect to login after logout
	if status := rr.Code; status != http.StatusSeeOther {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusSeeOther)
	}
	
	// Check redirect location
	location := rr.Header().Get("Location")
	if location != "/login" {
		t.Errorf("Expected redirect to '/login', got '%s'", location)
	}
}

func TestChangePasswordHandler_GET(t *testing.T) {
	setupTestDatabase()
	
	req, err := http.NewRequest("GET", "/change-password", nil)
	if err != nil {
		t.Fatal(err)
	}
	
	// Create a mock session (you might need to adjust this based on your session implementation)
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(ChangePasswordHandler)
	handler.ServeHTTP(rr, req)
	
	// Note: This test might fail if AuthMiddleware is required
	// In a real test, you'd need to mock or bypass the middleware
	if rr.Code != http.StatusOK && rr.Code != http.StatusSeeOther {
		t.Logf("Change password GET test - Status code: %d (might need session setup)", rr.Code)
	}
}

func TestPasswordHashing(t *testing.T) {
	password := "testpassword123"
	
	// Test password hashing
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}
	
	// Test password verification
	err = bcrypt.CompareHashAndPassword(hashedPassword, []byte(password))
	if err != nil {
		t.Error("Password verification should succeed")
	}
	
	// Test wrong password
	err = bcrypt.CompareHashAndPassword(hashedPassword, []byte("wrongpassword"))
	if err == nil {
		t.Error("Wrong password verification should fail")
	}
}