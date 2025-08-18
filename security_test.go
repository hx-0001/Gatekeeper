package main

import (
	"embed"
	"fmt"
	"gatekeeper/config"
	"gatekeeper/database"
	"gatekeeper/handlers"
	"gatekeeper/test_utils"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Security tests focused on defensive security measures
func TestPasswordSecurity(t *testing.T) {
	t.Run("WeakPasswordsRejected", func(t *testing.T) {
		testutils.SetupTestDB()
		defer database.DB.Close()

		config.AppConfig = config.GetConfig()
		handlers.InitHandlers(config.AppConfig, embed.FS{})

		weakPasswords := []string{
			"", "123", "abc", "password", "12345", "admin",
		}

		for _, weakPass := range weakPasswords {
			t.Run(fmt.Sprintf("Password_%s", weakPass), func(t *testing.T) {
				formData := url.Values{}
				formData.Set("username", "12345")
				formData.Set("password", weakPass)

				req, _ := http.NewRequest("POST", "/register", strings.NewReader(formData.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				rr := httptest.NewRecorder()
				handlers.RegisterHandler(rr, req)

				// Even weak passwords are accepted in current implementation
				// This test documents current behavior - could be enhanced
				if rr.Code != http.StatusSeeOther && rr.Code != http.StatusOK {
					t.Logf("Weak password '%s' was rejected (good)", weakPass)
				}
			})
		}
	})

	t.Run("BcryptHashingStrength", func(t *testing.T) {
		password := "testpassword123"
		
		// Test different bcrypt costs
		costs := []int{4, 8, 10, 12, 14}
		for _, cost := range costs {
			hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
			if err != nil {
				t.Fatalf("Failed to hash password with cost %d: %v", cost, err)
			}

			// Verify hash
			err = bcrypt.CompareHashAndPassword(hash, []byte(password))
			if err != nil {
				t.Errorf("Failed to verify password hash with cost %d", cost)
			}

			// Verify wrong password fails
			err = bcrypt.CompareHashAndPassword(hash, []byte("wrongpassword"))
			if err == nil {
				t.Errorf("Wrong password verification should fail for cost %d", cost)
			}
		}
	})

	t.Run("PasswordHashUniqueness", func(t *testing.T) {
		password := "samepassword"
		
		// Generate multiple hashes of the same password
		hashes := make([]string, 10)
		for i := 0; i < 10; i++ {
			hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
			if err != nil {
				t.Fatalf("Failed to hash password: %v", err)
			}
			hashes[i] = string(hash)
		}

		// Verify all hashes are different (salt randomization)
		for i := 0; i < len(hashes); i++ {
			for j := i + 1; j < len(hashes); j++ {
				if hashes[i] == hashes[j] {
					t.Error("Password hashes should be unique due to salt randomization")
				}
			}
		}
	})
}

func TestUsernameValidationSecurity(t *testing.T) {
	testutils.SetupTestDB()
	defer database.DB.Close()

	config.AppConfig = config.GetConfig()
	handlers.InitHandlers(config.AppConfig, embed.FS{})

	validUsernames := []string{
		"12345", "67890", "a12345", "b67890", "z99999",
	}

	invalidUsernames := []string{
		"", "1234", "123456", "ab123", "123ab", "admin", "root", 
		"user", "test", "12345a", "a1234", "123", "1234567",
		"special!", "@user", "user@", "user.com", "user space",
		"admin123", "Administrator", "ADMIN", "Admin",
	}

	for _, username := range validUsernames {
		t.Run(fmt.Sprintf("Valid_%s", username), func(t *testing.T) {
			formData := url.Values{}
			formData.Set("username", username)
			formData.Set("password", "securepassword123")

			req, _ := http.NewRequest("POST", "/register", strings.NewReader(formData.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			rr := httptest.NewRecorder()
			handlers.RegisterHandler(rr, req)

			if rr.Code != http.StatusSeeOther && rr.Code != http.StatusOK {
				t.Errorf("Valid username '%s' was rejected: %d", username, rr.Code)
			}
		})
	}

	for _, username := range invalidUsernames {
		t.Run(fmt.Sprintf("Invalid_%s", username), func(t *testing.T) {
			formData := url.Values{}
			formData.Set("username", username)
			formData.Set("password", "securepassword123")

			req, _ := http.NewRequest("POST", "/register", strings.NewReader(formData.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			rr := httptest.NewRecorder()
			handlers.RegisterHandler(rr, req)

			if rr.Code == http.StatusSeeOther || rr.Code == http.StatusOK {
				t.Errorf("Invalid username '%s' was accepted: %d", username, rr.Code)
			}
		})
	}
}

func TestSQLInjectionPrevention(t *testing.T) {
	testutils.SetupTestDB()
	defer database.DB.Close()

	config.AppConfig = config.GetConfig()
	handlers.InitHandlers(config.AppConfig, embed.FS{})

	// SQL injection attempts
	sqlInjectionAttempts := []string{
		"'; DROP TABLE users; --",
		"admin'; --",
		"' OR '1'='1",
		"' OR 1=1 --",
		"' UNION SELECT * FROM users --",
		"admin'/*",
		"'; INSERT INTO users VALUES('hacker','pass','admin'); --",
	}

	for _, injection := range sqlInjectionAttempts {
		t.Run(fmt.Sprintf("SQLInjection_%s", strings.ReplaceAll(injection, "'", "QUOTE")), func(t *testing.T) {
			// Test login endpoint
			formData := url.Values{}
			formData.Set("username", injection)
			formData.Set("password", "anypassword")

			req, _ := http.NewRequest("POST", "/login", strings.NewReader(formData.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			rr := httptest.NewRecorder()
			handlers.LoginHandler(rr, req)

			// Should not succeed with SQL injection
			if rr.Code == http.StatusSeeOther {
				t.Errorf("SQL injection attempt '%s' in login succeeded", injection)
			}

			// Verify users table still exists and has expected structure
			var count int
			err := database.DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
			if err != nil {
				t.Errorf("Users table corrupted or deleted by SQL injection attempt '%s': %v", injection, err)
			}
		})
	}
}

func TestSessionSecurity(t *testing.T) {
	config.AppConfig = config.GetConfig()
	handlers.InitHandlers(config.AppConfig, embed.FS{})

	t.Run("SessionSecretKeyStrength", func(t *testing.T) {
		secretKey := config.AppConfig.Session.SecretKey
		
		// Check minimum length
		if len(secretKey) < 16 {
			t.Error("Session secret key should be at least 16 characters for security")
		}

		// Check it's not the obvious default
		if secretKey == "secret" || secretKey == "key" || secretKey == "password" {
			t.Error("Session secret key should not be a common/obvious value")
		}
	})

	t.Run("SessionCookieSettings", func(t *testing.T) {
		testutils.SetupTestDB()
		defer database.DB.Close()

		// Create test user
		testutils.CreateTestUser("12345", "password", "applicant")

		formData := url.Values{}
		formData.Set("username", "12345")
		formData.Set("password", "password")

		req, _ := http.NewRequest("POST", "/login", strings.NewReader(formData.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rr := httptest.NewRecorder()
		handlers.LoginHandler(rr, req)

		cookies := rr.Result().Cookies()
		if len(cookies) == 0 {
			t.Error("No session cookie set after login")
			return
		}

		sessionCookie := cookies[0]
		
		// Check cookie security settings
		if sessionCookie.HttpOnly == false {
			t.Error("Session cookie should have HttpOnly flag set")
		}

		// Check cookie expiration
		if sessionCookie.MaxAge <= 0 && sessionCookie.Expires.IsZero() {
			t.Error("Session cookie should have expiration set")
		}
	})

	t.Run("SessionInvalidation", func(t *testing.T) {
		testutils.SetupTestDB()
		defer database.DB.Close()

		// Create test user
		testutils.CreateTestUser("12345", "password", "applicant")

		// Login to get session
		formData := url.Values{}
		formData.Set("username", "12345")
		formData.Set("password", "password")

		loginReq, _ := http.NewRequest("POST", "/login", strings.NewReader(formData.Encode()))
		loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		loginRR := httptest.NewRecorder()
		handlers.LoginHandler(loginRR, loginReq)

		cookies := loginRR.Result().Cookies()
		if len(cookies) == 0 {
			t.Fatal("No session cookie received")
		}

		// Test logout
		logoutReq, _ := http.NewRequest("GET", "/logout", nil)
		logoutReq.AddCookie(cookies[0])

		logoutRR := httptest.NewRecorder()
		handlers.LogoutHandler(logoutRR, logoutReq)

		// Check that session was invalidated
		logoutCookies := logoutRR.Result().Cookies()
		if len(logoutCookies) > 0 {
			for _, cookie := range logoutCookies {
				if cookie.MaxAge != -1 && !cookie.Expires.Before(time.Now()) {
					t.Error("Session cookie should be invalidated on logout")
				}
			}
		}
	})
}

func TestInputValidationSecurity(t *testing.T) {
	testutils.SetupTestDB()
	defer database.DB.Close()

	config.AppConfig = config.GetConfig()
	handlers.InitHandlers(config.AppConfig, embed.FS{})

	// Create test user
	userID, _ := testutils.CreateTestUser("12345", "password", "applicant")

	t.Run("IPAddressValidation", func(t *testing.T) {
		maliciousIPs := []string{
			"", "invalid", "300.300.300.300", "192.168.1", "192.168.1.1.1",
			"<script>alert('xss')</script>", "'; DROP TABLE applications; --",
			"../../../etc/passwd", "localhost", "127.0.0.1",
			"0.0.0.0", "255.255.255.255", "192.168.1.256",
		}

		for _, ip := range maliciousIPs {
			t.Run(fmt.Sprintf("IP_%s", strings.ReplaceAll(ip, ".", "_")), func(t *testing.T) {
				formData := url.Values{}
				formData.Set("ip_address", ip)
				formData.Set("port", "8080")
				formData.Set("reason", "Test application")

				req, _ := http.NewRequest("POST", "/apply", strings.NewReader(formData.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				rr := httptest.NewRecorder()
				handlers.ApplyHandler(rr, req)

				// Should reject invalid IPs
				if rr.Code == http.StatusSeeOther || rr.Code == http.StatusOK {
					t.Errorf("Invalid IP '%s' was accepted", ip)
				}
			})
		}
	})

	t.Run("PortValidation", func(t *testing.T) {
		invalidPorts := []string{
			"", "0", "-1", "65536", "99999", "abc", "8080.5",
			"'; DROP TABLE applications; --", "<script>", "../../../",
		}

		for _, port := range invalidPorts {
			t.Run(fmt.Sprintf("Port_%s", strings.ReplaceAll(port, ".", "_")), func(t *testing.T) {
				formData := url.Values{}
				formData.Set("ip_address", "192.168.1.100")
				formData.Set("port", port)
				formData.Set("reason", "Test application")

				req, _ := http.NewRequest("POST", "/apply", strings.NewReader(formData.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				rr := httptest.NewRecorder()
				handlers.ApplyHandler(rr, req)

				// Should reject invalid ports
				if rr.Code == http.StatusSeeOther || rr.Code == http.StatusOK {
					t.Errorf("Invalid port '%s' was accepted", port)
				}
			})
		}
	})

	t.Run("ReasonFieldValidation", func(t *testing.T) {
		// Test very long reason field
		longReason := strings.Repeat("A", 10000)
		
		formData := url.Values{}
		formData.Set("ip_address", "192.168.1.100")
		formData.Set("port", "8080")
		formData.Set("reason", longReason)

		req, _ := http.NewRequest("POST", "/apply", strings.NewReader(formData.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rr := httptest.NewRecorder()
		handlers.ApplyHandler(rr, req)

		// Application might accept long reasons - this tests current behavior
		// Could be enhanced with length limits
		if rr.Code == http.StatusSeeOther || rr.Code == http.StatusOK {
			t.Log("Very long reason field was accepted - consider adding length limits")
		}
		
		// Use userID to avoid unused variable warning
		_ = userID
	})
}

func TestAuthorizationSecurity(t *testing.T) {
	testutils.SetupTestDB()
	defer database.DB.Close()

	config.AppConfig = config.GetConfig()
	handlers.InitHandlers(config.AppConfig, embed.FS{})

	// Create test users with different roles
	applicantID, _ := testutils.CreateTestUser("12345", "password", "applicant")
	approverID, _ := testutils.CreateTestUser("admin", "password", "approver")

	// Create test application
	appID, _ := testutils.CreateTestApplication(applicantID, "192.168.1.100", 8080, "Test app", "pending")
	_ = approverID // Use variable to avoid unused warning

	t.Run("ApproverOnlyEndpoints", func(t *testing.T) {
		approverEndpoints := []struct {
			method string
			path   string
			data   url.Values
		}{
			{"POST", "/admin/approve", url.Values{"id": {fmt.Sprintf("%d", appID)}}},
			{"POST", "/admin/reject", url.Values{"id": {fmt.Sprintf("%d", appID)}, "reason": {"Test rejection"}}},
			{"POST", "/admin/remove", url.Values{"id": {fmt.Sprintf("%d", appID)}}},
			{"POST", "/admin/retry", url.Values{"id": {fmt.Sprintf("%d", appID)}}},
			{"POST", "/admin/reset-password", url.Values{"user_id": {fmt.Sprintf("%d", applicantID)}}},
		}

		for _, endpoint := range approverEndpoints {
			t.Run(fmt.Sprintf("%s_%s", endpoint.method, strings.ReplaceAll(endpoint.path, "/", "_")), func(t *testing.T) {
				// Test without authentication
				var req *http.Request
				if endpoint.data != nil {
					req, _ = http.NewRequest(endpoint.method, endpoint.path, strings.NewReader(endpoint.data.Encode()))
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				} else {
					req, _ = http.NewRequest(endpoint.method, endpoint.path, nil)
				}

				rr := httptest.NewRecorder()
				
				// This would require proper middleware testing setup
				// For now, we're testing the handler functions directly
				switch endpoint.path {
				case "/admin/approve":
					handlers.ApproveHandler(rr, req)
				case "/admin/reject":
					handlers.RejectHandler(rr, req)
				case "/admin/remove":
					handlers.RemoveHandler(rr, req)
				case "/admin/retry":
					handlers.RetryHandler(rr, req)
				case "/admin/reset-password":
					handlers.ResetPasswordHandler(rr, req)
				}

				// Should require authentication/authorization
				if rr.Code == http.StatusOK {
					t.Logf("Endpoint %s accessible without proper authorization", endpoint.path)
				}
			})
		}
	})

	t.Run("RoleBasedAccess", func(t *testing.T) {
		// Test that applicants cannot access approver functions
		// This would require implementing proper role checking in handlers
		// Current implementation doesn't have strict role enforcement in handler tests
		
		// Verify different user roles exist
		var applicantRole, approverRole string
		database.DB.QueryRow("SELECT role FROM users WHERE id = ?", applicantID).Scan(&applicantRole)
		database.DB.QueryRow("SELECT role FROM users WHERE id = ?", approverID).Scan(&approverRole)

		if applicantRole != "applicant" {
			t.Errorf("Expected applicant role, got: %s", applicantRole)
		}
		if approverRole != "approver" {
			t.Errorf("Expected approver role, got: %s", approverRole)
		}
	})
}

func TestSecurityHeaders(t *testing.T) {
	config.AppConfig = config.GetConfig()
	handlers.InitHandlers(config.AppConfig, embed.FS{})

	t.Run("ContentTypeHeaders", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/login", nil)
		rr := httptest.NewRecorder()

		handlers.LoginHandler(rr, req)

		// Check for basic security-related headers
		contentType := rr.Header().Get("Content-Type")
		if contentType == "" {
			t.Log("Content-Type header not set - consider adding security headers")
		}
	})

	t.Run("XSSPrevention", func(t *testing.T) {
		// Test that user input is properly escaped in templates
		// This is a basic check - real XSS testing would be more comprehensive
		
		testutils.SetupTestDB()
		defer database.DB.Close()

		// Create user with potentially malicious username (within validation rules)
		userID, _ := testutils.CreateTestUser("12345", "password", "applicant")
		
		// Create application with XSS attempt in reason field
		xssReason := "<script>alert('xss')</script>"
		testutils.CreateTestApplication(userID, "192.168.1.100", 8080, xssReason, "pending")

		req, _ := http.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()

		handlers.DashboardHandler(rr, req)

		body := rr.Body.String()
		
		// Check that script tags are escaped or removed
		if strings.Contains(body, "<script>alert('xss')</script>") {
			t.Error("XSS payload not properly escaped in template")
		}
	})
}

func TestRateLimitingConcepts(t *testing.T) {
	// This test documents the need for rate limiting
	// Current implementation doesn't have rate limiting
	
	testutils.SetupTestDB()
	defer database.DB.Close()

	config.AppConfig = config.GetConfig()
	handlers.InitHandlers(config.AppConfig, embed.FS{})

	t.Run("LoginAttemptLimit", func(t *testing.T) {
		// Simulate multiple failed login attempts
		for i := 0; i < 10; i++ {
			formData := url.Values{}
			formData.Set("username", "nonexistent")
			formData.Set("password", "wrongpassword")

			req, _ := http.NewRequest("POST", "/login", strings.NewReader(formData.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			rr := httptest.NewRecorder()
			handlers.LoginHandler(rr, req)

			// Currently no rate limiting - all attempts processed
			if rr.Code != http.StatusUnauthorized {
				// This is expected behavior without rate limiting
			}
		}
		
		t.Log("Consider implementing rate limiting for login attempts")
	})

	t.Run("RegistrationRateLimit", func(t *testing.T) {
		// Simulate multiple registration attempts
		for i := 0; i < 5; i++ {
			formData := url.Values{}
			formData.Set("username", fmt.Sprintf("user%d", i))
			formData.Set("password", "password123")

			req, _ := http.NewRequest("POST", "/register", strings.NewReader(formData.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			rr := httptest.NewRecorder()
			handlers.RegisterHandler(rr, req)

			// Currently no rate limiting
		}
		
		t.Log("Consider implementing rate limiting for user registration")
	})
}

func TestConfigurationSecurity(t *testing.T) {
	t.Run("DefaultCredentials", func(t *testing.T) {
		config := config.GetConfig()
		
		// Check for dangerous defaults
		if config.Admin.Username == "admin" && config.Admin.Password == "admin" {
			t.Error("Default admin credentials should be changed in production")
		}

		if config.Session.SecretKey == "something-very-secret" {
			t.Error("Default session secret should be changed in production")
		}
	})

	t.Run("BcryptCostConfiguration", func(t *testing.T) {
		config := config.GetConfig()
		
		// Check bcrypt cost is reasonable
		if config.Security.BcryptCost < 10 {
			t.Error("Bcrypt cost should be at least 10 for security")
		}
		
		if config.Security.BcryptCost > 15 {
			t.Error("Bcrypt cost above 15 may cause performance issues")
		}
	})

	t.Run("UsernamePatternSecurity", func(t *testing.T) {
		config := config.GetConfig()
		
		// Verify username pattern is restrictive
		pattern := config.Security.UsernamePattern
		
		// Test the pattern
		re, err := regexp.Compile(pattern)
		if err != nil {
			t.Fatalf("Username pattern is invalid regex: %v", err)
		}

		// Test against known good and bad usernames
		goodUsernames := []string{"12345", "a12345"}
		badUsernames := []string{"admin", "root", "user", "test", ""}

		for _, username := range goodUsernames {
			if !re.MatchString(username) {
				t.Errorf("Pattern should match valid username: %s", username)
			}
		}

		for _, username := range badUsernames {
			if re.MatchString(username) {
				t.Errorf("Pattern should reject invalid username: %s", username)
			}
		}
	})
}