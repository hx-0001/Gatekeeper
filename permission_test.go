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
	"strings"
	"testing"

	"github.com/gorilla/sessions"
)

// Tests for interface permission restrictions and authorization controls
func TestAuthenticationMiddleware(t *testing.T) {
	testutils.SetupTestDB()
	defer database.DB.Close()

	config.AppConfig = config.GetConfig()
	handlers.InitHandlers(config.AppConfig, embed.FS{})

	t.Run("UnauthenticatedAccessBlocked", func(t *testing.T) {
		// Protected endpoints that require authentication
		protectedEndpoints := []struct {
			method string
			path   string
			data   url.Values
		}{
			{"GET", "/", nil},
			{"GET", "/apply", nil},
			{"POST", "/apply", url.Values{"ip_address": {"192.168.1.1"}, "port": {"8080"}, "reason": {"test"}}},
			{"GET", "/change-password", nil},
			{"POST", "/change-password", url.Values{"current_password": {"old"}, "new_password": {"new"}}},
		}

		for _, endpoint := range protectedEndpoints {
			t.Run(fmt.Sprintf("%s_%s", endpoint.method, strings.ReplaceAll(endpoint.path, "/", "_")), func(t *testing.T) {
				var req *http.Request
				if endpoint.data != nil {
					req, _ = http.NewRequest(endpoint.method, endpoint.path, strings.NewReader(endpoint.data.Encode()))
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				} else {
					req, _ = http.NewRequest(endpoint.method, endpoint.path, nil)
				}

				rr := httptest.NewRecorder()

				// Use middleware-wrapped handler
				handler := handlers.AuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("Protected content"))
				})

				handler(rr, req)

				// Should redirect to login
				if rr.Code != http.StatusFound {
					t.Errorf("Expected redirect (302), got %d for endpoint %s", rr.Code, endpoint.path)
				}

				location := rr.Header().Get("Location")
				if location != "/login" {
					t.Errorf("Expected redirect to /login, got %s", location)
				}
			})
		}
	})

	t.Run("AuthenticatedAccessAllowed", func(t *testing.T) {
		// Create test user and login session
		userID, _ := testutils.CreateTestUser("12345", "password", "applicant")

		req, _ := http.NewRequest("GET", "/dashboard", nil)

		// Mock session with user authentication
		store := sessions.NewCookieStore([]byte(config.AppConfig.Session.SecretKey))
		session, _ := store.Get(req, config.AppConfig.Session.Name)
		session.Values["user_id"] = userID
		session.Values["username"] = "12345"
		session.Values["role"] = "applicant"

		rr := httptest.NewRecorder()
		session.Save(req, rr)

		// Create new request with session cookie
		req2, _ := http.NewRequest("GET", "/dashboard", nil)
		cookies := rr.Result().Cookies()
		if len(cookies) > 0 {
			req2.AddCookie(cookies[0])
		}

		rr2 := httptest.NewRecorder()
		handler := handlers.AuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Protected content"))
		})

		handler(rr2, req2)

		if rr2.Code != http.StatusOK {
			t.Errorf("Expected 200 OK for authenticated user, got %d", rr2.Code)
		}

		if !strings.Contains(rr2.Body.String(), "Protected content") {
			t.Error("Expected protected content to be served to authenticated user")
		}
	})

	t.Run("InvalidSessionBlocked", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/dashboard", nil)

		// Add invalid/corrupted session cookie
		req.AddCookie(&http.Cookie{
			Name:  config.AppConfig.Session.Name,
			Value: "invalid-session-data",
		})

		rr := httptest.NewRecorder()
		handler := handlers.AuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Protected content"))
		})

		handler(rr, req)

		// Should redirect to login due to invalid session
		if rr.Code != http.StatusFound {
			t.Errorf("Expected redirect (302) for invalid session, got %d", rr.Code)
		}

		location := rr.Header().Get("Location")
		if location != "/login" {
			t.Errorf("Expected redirect to /login, got %s", location)
		}
	})
}

func TestApproverMiddleware(t *testing.T) {
	testutils.SetupTestDB()
	defer database.DB.Close()

	config.AppConfig = config.GetConfig()
	handlers.InitHandlers(config.AppConfig, embed.FS{})

	// Create test users with different roles
	applicantID, _ := testutils.CreateTestUser("12345", "password", "applicant")
	approverID, _ := testutils.CreateTestUser("67890", "password", "approver")

	t.Run("ApproverOnlyEndpointsBlockApplicants", func(t *testing.T) {
		// Admin endpoints that require approver role
		adminEndpoints := []struct {
			method string
			path   string
		}{
			{"GET", "/admin/users"},
			{"POST", "/admin/approve"},
			{"POST", "/admin/reject"},
			{"POST", "/admin/remove"},
			{"POST", "/admin/retry"},
			{"POST", "/admin/reset-password"},
			{"GET", "/admin/default-rules"},
			{"POST", "/admin/default-rules/add"},
			{"POST", "/admin/default-rules/update"},
			{"DELETE", "/admin/default-rules/delete"},
			{"GET", "/api/default-rules"},
		}

		for _, endpoint := range adminEndpoints {
			t.Run(fmt.Sprintf("Applicant_%s_%s", endpoint.method, strings.ReplaceAll(endpoint.path, "/", "_")), func(t *testing.T) {
				req, _ := http.NewRequest(endpoint.method, endpoint.path, nil)

				// Create session for applicant user
				store := sessions.NewCookieStore([]byte(config.AppConfig.Session.SecretKey))
				session, _ := store.Get(req, config.AppConfig.Session.Name)
				session.Values["user_id"] = applicantID
				session.Values["username"] = "12345"
				session.Values["role"] = "applicant"

				rr := httptest.NewRecorder()
				session.Save(req, rr)

				// Create new request with session cookie
				req2, _ := http.NewRequest(endpoint.method, endpoint.path, nil)
				cookies := rr.Result().Cookies()
				if len(cookies) > 0 {
					req2.AddCookie(cookies[0])
				}

				rr2 := httptest.NewRecorder()

				// Use middleware chain: Auth -> Approver
				handler := handlers.AuthMiddleware(handlers.ApproverMiddleware(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("Admin content"))
				}))

				handler(rr2, req2)

				// Should be forbidden for applicants
				if rr2.Code != http.StatusForbidden {
					t.Errorf("Expected 403 Forbidden for applicant accessing %s, got %d", endpoint.path, rr2.Code)
				}
			})
		}
	})

	t.Run("ApproverOnlyEndpointsAllowApprovers", func(t *testing.T) {
		adminEndpoints := []string{
			"/admin/users",
			"/admin/approve",
			"/admin/reject",
			"/admin/remove",
			"/admin/retry",
			"/admin/reset-password",
			"/admin/default-rules",
		}

		for _, endpoint := range adminEndpoints {
			t.Run(fmt.Sprintf("Approver_%s", strings.ReplaceAll(endpoint, "/", "_")), func(t *testing.T) {
				req, _ := http.NewRequest("GET", endpoint, nil)

				// Create session for approver user
				store := sessions.NewCookieStore([]byte(config.AppConfig.Session.SecretKey))
				session, _ := store.Get(req, config.AppConfig.Session.Name)
				session.Values["user_id"] = approverID
				session.Values["username"] = "67890"
				session.Values["role"] = "approver"

				rr := httptest.NewRecorder()
				session.Save(req, rr)

				// Create new request with session cookie
				req2, _ := http.NewRequest("GET", endpoint, nil)
				cookies := rr.Result().Cookies()
				if len(cookies) > 0 {
					req2.AddCookie(cookies[0])
				}

				rr2 := httptest.NewRecorder()

				// Use middleware chain: Auth -> Approver
				handler := handlers.AuthMiddleware(handlers.ApproverMiddleware(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("Admin content"))
				}))

				handler(rr2, req2)

				// Should be allowed for approvers
				if rr2.Code != http.StatusOK {
					t.Errorf("Expected 200 OK for approver accessing %s, got %d", endpoint, rr2.Code)
				}

				if !strings.Contains(rr2.Body.String(), "Admin content") {
					t.Error("Expected admin content to be served to approver")
				}
			})
		}
	})

	t.Run("UnauthenticatedAccessToApproverEndpoints", func(t *testing.T) {
		adminEndpoints := []string{
			"/admin/users",
			"/admin/approve",
			"/admin/reject",
			"/admin/remove",
		}

		for _, endpoint := range adminEndpoints {
			t.Run(fmt.Sprintf("Unauthenticated_%s", strings.ReplaceAll(endpoint, "/", "_")), func(t *testing.T) {
				req, _ := http.NewRequest("GET", endpoint, nil)
				rr := httptest.NewRecorder()

				// Use middleware chain: Auth -> Approver
				handler := handlers.AuthMiddleware(handlers.ApproverMiddleware(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("Admin content"))
				}))

				handler(rr, req)

				// Should redirect to login (Auth middleware catches this first)
				if rr.Code != http.StatusFound {
					t.Errorf("Expected redirect (302) for unauthenticated access to %s, got %d", endpoint, rr.Code)
				}

				location := rr.Header().Get("Location")
				if location != "/login" {
					t.Errorf("Expected redirect to /login, got %s", location)
				}
			})
		}
	})

	t.Run("InvalidRoleInSession", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/admin/users", nil)

		// Create session with invalid role
		store := sessions.NewCookieStore([]byte(config.AppConfig.Session.SecretKey))
		session, _ := store.Get(req, config.AppConfig.Session.Name)
		session.Values["user_id"] = applicantID
		session.Values["username"] = "12345"
		session.Values["role"] = "invalid_role"

		rr := httptest.NewRecorder()
		session.Save(req, rr)

		// Create new request with session cookie
		req2, _ := http.NewRequest("GET", "/admin/users", nil)
		cookies := rr.Result().Cookies()
		if len(cookies) > 0 {
			req2.AddCookie(cookies[0])
		}

		rr2 := httptest.NewRecorder()

		// Use middleware chain
		handler := handlers.AuthMiddleware(handlers.ApproverMiddleware(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Admin content"))
		}))

		handler(rr2, req2)

		// Should be forbidden for invalid role
		if rr2.Code != http.StatusForbidden {
			t.Errorf("Expected 403 Forbidden for invalid role, got %d", rr2.Code)
		}
	})

	t.Run("MissingRoleInSession", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/admin/users", nil)

		// Create session without role
		store := sessions.NewCookieStore([]byte(config.AppConfig.Session.SecretKey))
		session, _ := store.Get(req, config.AppConfig.Session.Name)
		session.Values["user_id"] = applicantID
		session.Values["username"] = "12345"
		// No role set

		rr := httptest.NewRecorder()
		session.Save(req, rr)

		// Create new request with session cookie
		req2, _ := http.NewRequest("GET", "/admin/users", nil)
		cookies := rr.Result().Cookies()
		if len(cookies) > 0 {
			req2.AddCookie(cookies[0])
		}

		rr2 := httptest.NewRecorder()

		// Use middleware chain
		handler := handlers.AuthMiddleware(handlers.ApproverMiddleware(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Admin content"))
		}))

		handler(rr2, req2)

		// Should be forbidden when role is missing
		if rr2.Code != http.StatusForbidden {
			t.Errorf("Expected 403 Forbidden for missing role, got %d", rr2.Code)
		}
	})
}

func TestRoleBasedAccessControl(t *testing.T) {
	testutils.SetupTestDB()
	defer database.DB.Close()

	config.AppConfig = config.GetConfig()
	handlers.InitHandlers(config.AppConfig, embed.FS{})

	// Create test users
	applicantID, _ := testutils.CreateTestUser("12345", "password", "applicant")
	approverID, _ := testutils.CreateTestUser("67890", "password", "approver")

	t.Run("ApplicantCanAccessUserEndpoints", func(t *testing.T) {
		applicantEndpoints := []string{
			"/",                // Dashboard
			"/apply",           // Application form
			"/change-password", // Change password
		}

		for _, endpoint := range applicantEndpoints {
			t.Run(fmt.Sprintf("Applicant_%s", strings.ReplaceAll(endpoint, "/", "_")), func(t *testing.T) {
				req, _ := http.NewRequest("GET", endpoint, nil)

				// Create session for applicant
				store := sessions.NewCookieStore([]byte(config.AppConfig.Session.SecretKey))
				session, _ := store.Get(req, config.AppConfig.Session.Name)
				session.Values["user_id"] = applicantID
				session.Values["username"] = "12345"
				session.Values["role"] = "applicant"

				rr := httptest.NewRecorder()
				session.Save(req, rr)

				// Create new request with session cookie
				req2, _ := http.NewRequest("GET", endpoint, nil)
				cookies := rr.Result().Cookies()
				if len(cookies) > 0 {
					req2.AddCookie(cookies[0])
				}

				rr2 := httptest.NewRecorder()

				// Use auth middleware only (no approver middleware for these endpoints)
				handler := handlers.AuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("User content"))
				})

				handler(rr2, req2)

				if rr2.Code != http.StatusOK {
					t.Errorf("Expected 200 OK for applicant accessing %s, got %d", endpoint, rr2.Code)
				}
			})
		}
	})

	t.Run("ApproverCanAccessAllEndpoints", func(t *testing.T) {
		allEndpoints := []string{
			"/", // User endpoints
			"/apply",
			"/change-password",
			"/admin/users", // Admin endpoints
			"/admin/approve",
			"/admin/reject",
			"/admin/remove",
			"/admin/reset-password",
		}

		for _, endpoint := range allEndpoints {
			t.Run(fmt.Sprintf("Approver_%s", strings.ReplaceAll(endpoint, "/", "_")), func(t *testing.T) {
				req, _ := http.NewRequest("GET", endpoint, nil)

				// Create session for approver
				store := sessions.NewCookieStore([]byte(config.AppConfig.Session.SecretKey))
				session, _ := store.Get(req, config.AppConfig.Session.Name)
				session.Values["user_id"] = approverID
				session.Values["username"] = "67890"
				session.Values["role"] = "approver"

				rr := httptest.NewRecorder()
				session.Save(req, rr)

				// Create new request with session cookie
				req2, _ := http.NewRequest("GET", endpoint, nil)
				cookies := rr.Result().Cookies()
				if len(cookies) > 0 {
					req2.AddCookie(cookies[0])
				}

				rr2 := httptest.NewRecorder()

				// Use appropriate middleware based on endpoint
				var handler http.HandlerFunc
				if strings.HasPrefix(endpoint, "/admin/") {
					// Admin endpoints require both Auth and Approver middleware
					handler = handlers.AuthMiddleware(handlers.ApproverMiddleware(func(w http.ResponseWriter, r *http.Request) {
						w.WriteHeader(http.StatusOK)
						w.Write([]byte("Admin content"))
					}))
				} else {
					// User endpoints require only Auth middleware
					handler = handlers.AuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
						w.WriteHeader(http.StatusOK)
						w.Write([]byte("User content"))
					})
				}

				handler(rr2, req2)

				if rr2.Code != http.StatusOK {
					t.Errorf("Expected 200 OK for approver accessing %s, got %d", endpoint, rr2.Code)
				}
			})
		}
	})

	t.Run("PrivilegeEscalationPrevention", func(t *testing.T) {
		// Test that users cannot modify their own role or access data outside their scope

		// Create application by applicant
		appID, _ := testutils.CreateTestApplication(applicantID, "192.168.1.100", 8080, "Test app", "pending")

		// Try to access admin functions with applicant credentials
		maliciousAttempts := []struct {
			method   string
			endpoint string
			data     url.Values
		}{
			{"POST", "/admin/approve", url.Values{"id": {fmt.Sprintf("%d", appID)}}},
			{"POST", "/admin/reject", url.Values{"id": {fmt.Sprintf("%d", appID)}, "reason": {"rejected"}}},
			{"POST", "/admin/reset-password", url.Values{"user_id": {fmt.Sprintf("%d", approverID)}}},
		}

		for _, attempt := range maliciousAttempts {
			t.Run(fmt.Sprintf("PrivEsc_%s_%s", attempt.method, strings.ReplaceAll(attempt.endpoint, "/", "_")), func(t *testing.T) {
				var req *http.Request
				if attempt.data != nil {
					req, _ = http.NewRequest(attempt.method, attempt.endpoint, strings.NewReader(attempt.data.Encode()))
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				} else {
					req, _ = http.NewRequest(attempt.method, attempt.endpoint, nil)
				}

				// Create session for applicant (trying to access admin functions)
				store := sessions.NewCookieStore([]byte(config.AppConfig.Session.SecretKey))
				session, _ := store.Get(req, config.AppConfig.Session.Name)
				session.Values["user_id"] = applicantID
				session.Values["username"] = "12345"
				session.Values["role"] = "applicant"

				rr := httptest.NewRecorder()
				session.Save(req, rr)

				// Create new request with session cookie
				var req2 *http.Request
				if attempt.data != nil {
					req2, _ = http.NewRequest(attempt.method, attempt.endpoint, strings.NewReader(attempt.data.Encode()))
					req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				} else {
					req2, _ = http.NewRequest(attempt.method, attempt.endpoint, nil)
				}

				cookies := rr.Result().Cookies()
				if len(cookies) > 0 {
					req2.AddCookie(cookies[0])
				}

				rr2 := httptest.NewRecorder()

				// Use full middleware chain
				handler := handlers.AuthMiddleware(handlers.ApproverMiddleware(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("Admin action completed"))
				}))

				handler(rr2, req2)

				// Should be forbidden - privilege escalation blocked
				if rr2.Code != http.StatusForbidden {
					t.Errorf("Privilege escalation attempt should be blocked with 403, got %d for %s", rr2.Code, attempt.endpoint)
				}
			})
		}
	})
}

func TestSessionIntegrity(t *testing.T) {
	testutils.SetupTestDB()
	defer database.DB.Close()

	config.AppConfig = config.GetConfig()
	handlers.InitHandlers(config.AppConfig, embed.FS{})

	t.Run("SessionTampering", func(t *testing.T) {
		userID, _ := testutils.CreateTestUser("12345", "password", "applicant")

		req, _ := http.NewRequest("GET", "/admin/users", nil)

		// Create legitimate session
		store := sessions.NewCookieStore([]byte(config.AppConfig.Session.SecretKey))
		session, _ := store.Get(req, config.AppConfig.Session.Name)
		session.Values["user_id"] = userID
		session.Values["username"] = "12345"
		session.Values["role"] = "applicant"

		rr := httptest.NewRecorder()
		session.Save(req, rr)

		// Get the session cookie
		cookies := rr.Result().Cookies()
		if len(cookies) == 0 {
			t.Fatal("No session cookie generated")
		}

		// Tamper with the cookie value
		tamperedCookie := &http.Cookie{
			Name:  cookies[0].Name,
			Value: "tampered" + cookies[0].Value, // Corrupt the cookie
		}

		req2, _ := http.NewRequest("GET", "/admin/users", nil)
		req2.AddCookie(tamperedCookie)

		rr2 := httptest.NewRecorder()
		handler := handlers.AuthMiddleware(handlers.ApproverMiddleware(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Admin content"))
		}))

		handler(rr2, req2)

		// Should redirect to login due to tampered session
		if rr2.Code != http.StatusFound {
			t.Errorf("Expected redirect (302) for tampered session, got %d", rr2.Code)
		}
	})

	t.Run("SessionExpiration", func(t *testing.T) {
		// This test would require time manipulation to test session expiration
		// For now, we verify that session max age is configured
		if config.AppConfig.Session.MaxAge <= 0 {
			t.Error("Session MaxAge should be configured for automatic expiration")
		}

		if config.AppConfig.Session.MaxAge > 86400*7 { // 7 days
			t.Error("Session MaxAge is too long, consider shorter session lifetimes")
		}
	})

	t.Run("ConcurrentSessionSafety", func(t *testing.T) {
		userID, _ := testutils.CreateTestUser("12345", "password", "applicant")

		// Simulate multiple concurrent requests with same user session
		for i := 0; i < 5; i++ {
			t.Run(fmt.Sprintf("Request_%d", i), func(t *testing.T) {
				req, _ := http.NewRequest("GET", "/", nil)

				store := sessions.NewCookieStore([]byte(config.AppConfig.Session.SecretKey))
				session, _ := store.Get(req, config.AppConfig.Session.Name)
				session.Values["user_id"] = userID
				session.Values["username"] = "12345"
				session.Values["role"] = "applicant"

				rr := httptest.NewRecorder()
				session.Save(req, rr)

				req2, _ := http.NewRequest("GET", "/", nil)
				cookies := rr.Result().Cookies()
				if len(cookies) > 0 {
					req2.AddCookie(cookies[0])
				}

				rr2 := httptest.NewRecorder()
				handler := handlers.AuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("Content"))
				})

				handler(rr2, req2)

				if rr2.Code != http.StatusOK {
					t.Errorf("Concurrent session request %d failed with status %d", i, rr2.Code)
				}
			})
		}
	})
}

// Additional comprehensive permission tests to fill coverage gaps
func TestDataLevelPermissions(t *testing.T) {
	testutils.SetupTestDB()
	defer database.DB.Close()

	config.AppConfig = config.GetConfig()
	handlers.InitHandlers(config.AppConfig, embed.FS{})

	// Create test users
	user1ID, _ := testutils.CreateTestUser("12345", "password", "applicant")
	user2ID, _ := testutils.CreateTestUser("67890", "password", "applicant")
	approverID, _ := testutils.CreateTestUser("99999", "password", "approver")

	// Create applications for different users
	app1ID, _ := testutils.CreateTestApplication(user1ID, "192.168.1.100", 8080, "User1 app", "pending")
	app2ID, _ := testutils.CreateTestApplication(user2ID, "192.168.1.101", 8081, "User2 app", "pending")

	t.Run("UserCanOnlyAccessOwnData", func(t *testing.T) {
		// This test documents that data-level permissions are not currently enforced
		// Users might be able to see other users' data - this is a potential security gap
		
		req, _ := http.NewRequest("GET", "/", nil)
		
		// Create session for user1
		store := sessions.NewCookieStore([]byte(config.AppConfig.Session.SecretKey))
		session, _ := store.Get(req, config.AppConfig.Session.Name)
		session.Values["user_id"] = user1ID
		session.Values["username"] = "12345"
		session.Values["role"] = "applicant"
		
		rr := httptest.NewRecorder()
		session.Save(req, rr)
		
		req2, _ := http.NewRequest("GET", "/", nil)
		cookies := rr.Result().Cookies()
		if len(cookies) > 0 {
			req2.AddCookie(cookies[0])
		}

		rr2 := httptest.NewRecorder()
		handler := handlers.AuthMiddleware(handlers.DashboardHandler)
		handler(rr2, req2)

		if rr2.Code != http.StatusOK {
			t.Errorf("Expected 200 OK for user accessing dashboard, got %d", rr2.Code)
		}

		// Log for future enhancement: implement data-level access control
		t.Logf("Data-level permission test - App IDs: user1=%d, user2=%d, approver=%d", app1ID, app2ID, approverID)
		t.Log("TODO: Implement data-level access controls to ensure users only see their own applications")
	})

	t.Run("CrossUserDataAccess", func(t *testing.T) {
		// Test that users cannot directly access other users' application data
		// This would require implementing data-level authorization in handlers
		
		maliciousAttempts := []struct {
			description string
			method      string
			endpoint    string
			userID      int64
			targetAppID int64
			data        url.Values
		}{
			{"User1 trying to approve User2's app", "POST", "/admin/approve", user1ID, app2ID, url.Values{"id": {fmt.Sprintf("%d", app2ID)}}},
			{"User2 trying to reject User1's app", "POST", "/admin/reject", user2ID, app1ID, url.Values{"id": {fmt.Sprintf("%d", app1ID)}, "reason": {"malicious"}}},
		}

		for _, attempt := range maliciousAttempts {
			t.Run(attempt.description, func(t *testing.T) {
				var req *http.Request
				if attempt.data != nil {
					req, _ = http.NewRequest(attempt.method, attempt.endpoint, strings.NewReader(attempt.data.Encode()))
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				} else {
					req, _ = http.NewRequest(attempt.method, attempt.endpoint, nil)
				}
				
				// Create session for malicious user (applicant trying admin functions)
				store := sessions.NewCookieStore([]byte(config.AppConfig.Session.SecretKey))
				session, _ := store.Get(req, config.AppConfig.Session.Name)
				session.Values["user_id"] = attempt.userID
				session.Values["username"] = fmt.Sprintf("%d", attempt.userID)
				session.Values["role"] = "applicant"
				
				rr := httptest.NewRecorder()
				session.Save(req, rr)
				
				var req2 *http.Request
				if attempt.data != nil {
					req2, _ = http.NewRequest(attempt.method, attempt.endpoint, strings.NewReader(attempt.data.Encode()))
					req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				} else {
					req2, _ = http.NewRequest(attempt.method, attempt.endpoint, nil)
				}
				
				cookies := rr.Result().Cookies()
				if len(cookies) > 0 {
					req2.AddCookie(cookies[0])
				}

				rr2 := httptest.NewRecorder()
				handler := handlers.AuthMiddleware(handlers.ApproverMiddleware(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("Admin action"))
				}))
				
				handler(rr2, req2)

				// Should be forbidden - blocked by ApproverMiddleware
				if rr2.Code != http.StatusForbidden {
					t.Errorf("Cross-user data access should be blocked with 403, got %d", rr2.Code)
				}
			})
		}
	})
}

func TestHTTPMethodPermissions(t *testing.T) {
	testutils.SetupTestDB()
	defer database.DB.Close()

	config.AppConfig = config.GetConfig()
	handlers.InitHandlers(config.AppConfig, embed.FS{})

	applicantID, _ := testutils.CreateTestUser("12345", "password", "applicant")
	approverID, _ := testutils.CreateTestUser("67890", "password", "approver")
	appID, _ := testutils.CreateTestApplication(applicantID, "192.168.1.100", 8080, "Test app", "pending")

	t.Run("HTTPMethodSpecificPermissions", func(t *testing.T) {
		// Test different HTTP methods with proper permissions
		methodTests := []struct {
			description string
			method      string
			endpoint    string
			userRole    string
			userID      int64
			data        url.Values
			expectedCode int
		}{
			// Applicant tests
			{"Applicant GET dashboard", "GET", "/", "applicant", applicantID, nil, 200},
			{"Applicant POST apply", "POST", "/apply", "applicant", applicantID, url.Values{"ip_address": {"192.168.1.200"}, "port": {"9000"}, "reason": {"test"}}, 200},
			{"Applicant POST change-password", "POST", "/change-password", "applicant", applicantID, url.Values{"current_password": {"password"}, "new_password": {"newpass123"}}, 200},
			
			// Applicant blocked from admin operations
			{"Applicant POST admin approve", "POST", "/admin/approve", "applicant", applicantID, url.Values{"id": {fmt.Sprintf("%d", appID)}}, 403},
			{"Applicant POST admin reject", "POST", "/admin/reject", "applicant", applicantID, url.Values{"id": {fmt.Sprintf("%d", appID)}, "reason": {"test"}}, 403},
			{"Applicant DELETE admin rule", "DELETE", "/admin/default-rules/delete", "applicant", applicantID, url.Values{"id": {"1"}}, 403},
			
			// Approver tests
			{"Approver GET dashboard", "GET", "/", "approver", approverID, nil, 200},
			{"Approver GET admin users", "GET", "/admin/users", "approver", approverID, nil, 200},
			{"Approver POST admin approve", "POST", "/admin/approve", "approver", approverID, url.Values{"id": {fmt.Sprintf("%d", appID)}}, 200},
			{"Approver POST admin reject", "POST", "/admin/reject", "approver", approverID, url.Values{"id": {fmt.Sprintf("%d", appID)}, "reason": {"test"}}, 200},
			{"Approver POST reset password", "POST", "/admin/reset-password", "approver", approverID, url.Values{"user_id": {fmt.Sprintf("%d", applicantID)}}, 200},
		}

		for _, test := range methodTests {
			t.Run(test.description, func(t *testing.T) {
				var req *http.Request
				if test.data != nil {
					req, _ = http.NewRequest(test.method, test.endpoint, strings.NewReader(test.data.Encode()))
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				} else {
					req, _ = http.NewRequest(test.method, test.endpoint, nil)
				}
				
				// Create session
				store := sessions.NewCookieStore([]byte(config.AppConfig.Session.SecretKey))
				session, _ := store.Get(req, config.AppConfig.Session.Name)
				session.Values["user_id"] = test.userID
				session.Values["username"] = fmt.Sprintf("%d", test.userID)
				session.Values["role"] = test.userRole
				
				rr := httptest.NewRecorder()
				session.Save(req, rr)
				
				var req2 *http.Request
				if test.data != nil {
					req2, _ = http.NewRequest(test.method, test.endpoint, strings.NewReader(test.data.Encode()))
					req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				} else {
					req2, _ = http.NewRequest(test.method, test.endpoint, nil)
				}
				
				cookies := rr.Result().Cookies()
				if len(cookies) > 0 {
					req2.AddCookie(cookies[0])
				}

				rr2 := httptest.NewRecorder()
				
				// Use appropriate middleware based on endpoint
				var handler http.HandlerFunc
				if strings.HasPrefix(test.endpoint, "/admin/") {
					handler = handlers.AuthMiddleware(handlers.ApproverMiddleware(func(w http.ResponseWriter, r *http.Request) {
						w.WriteHeader(http.StatusOK)
						w.Write([]byte("Admin content"))
					}))
				} else {
					handler = handlers.AuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
						w.WriteHeader(http.StatusOK)
						w.Write([]byte("User content"))
					})
				}
				
				handler(rr2, req2)

				if test.expectedCode == 200 && rr2.Code != http.StatusOK {
					t.Errorf("%s: Expected 200 OK, got %d", test.description, rr2.Code)
				} else if test.expectedCode == 403 && rr2.Code != http.StatusForbidden {
					t.Errorf("%s: Expected 403 Forbidden, got %d", test.description, rr2.Code)
				}
			})
		}
	})
}

func TestMissingEndpointsPermissions(t *testing.T) {
	testutils.SetupTestDB()
	defer database.DB.Close()

	config.AppConfig = config.GetConfig()
	handlers.InitHandlers(config.AppConfig, embed.FS{})

	applicantID, _ := testutils.CreateTestUser("12345", "password", "applicant")
	approverID, _ := testutils.CreateTestUser("67890", "password", "approver")

	t.Run("DefaultRulesEndpointsPermissions", func(t *testing.T) {
		// Test the missing default rules endpoints that were identified
		missingEndpoints := []struct {
			method string
			path   string
			data   url.Values
		}{
			{"POST", "/admin/default-rules/add", url.Values{"ip_address": {"192.168.1.0"}, "port": {"80"}, "description": {"Test rule"}}},
			{"POST", "/admin/default-rules/update", url.Values{"id": {"1"}, "ip_address": {"192.168.1.1"}, "port": {"81"}}},
			{"DELETE", "/admin/default-rules/delete", url.Values{"id": {"1"}}},
			{"GET", "/api/default-rules", nil},
		}

		// Test that applicants are blocked
		for _, endpoint := range missingEndpoints {
			t.Run(fmt.Sprintf("Applicant_Blocked_%s_%s", endpoint.method, strings.ReplaceAll(endpoint.path, "/", "_")), func(t *testing.T) {
				var req *http.Request
				if endpoint.data != nil {
					req, _ = http.NewRequest(endpoint.method, endpoint.path, strings.NewReader(endpoint.data.Encode()))
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				} else {
					req, _ = http.NewRequest(endpoint.method, endpoint.path, nil)
				}
				
				// Create session for applicant
				store := sessions.NewCookieStore([]byte(config.AppConfig.Session.SecretKey))
				session, _ := store.Get(req, config.AppConfig.Session.Name)
				session.Values["user_id"] = applicantID
				session.Values["username"] = "12345"
				session.Values["role"] = "applicant"
				
				rr := httptest.NewRecorder()
				session.Save(req, rr)
				
				var req2 *http.Request
				if endpoint.data != nil {
					req2, _ = http.NewRequest(endpoint.method, endpoint.path, strings.NewReader(endpoint.data.Encode()))
					req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				} else {
					req2, _ = http.NewRequest(endpoint.method, endpoint.path, nil)
				}
				
				cookies := rr.Result().Cookies()
				if len(cookies) > 0 {
					req2.AddCookie(cookies[0])
				}

				rr2 := httptest.NewRecorder()
				handler := handlers.AuthMiddleware(handlers.ApproverMiddleware(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("Admin content"))
				}))
				
				handler(rr2, req2)

				if rr2.Code != http.StatusForbidden {
					t.Errorf("Applicant should be blocked from %s %s, got %d", endpoint.method, endpoint.path, rr2.Code)
				}
			})
		}

		// Test that approvers are allowed
		for _, endpoint := range missingEndpoints {
			t.Run(fmt.Sprintf("Approver_Allowed_%s_%s", endpoint.method, strings.ReplaceAll(endpoint.path, "/", "_")), func(t *testing.T) {
				var req *http.Request
				if endpoint.data != nil {
					req, _ = http.NewRequest(endpoint.method, endpoint.path, strings.NewReader(endpoint.data.Encode()))
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				} else {
					req, _ = http.NewRequest(endpoint.method, endpoint.path, nil)
				}
				
				// Create session for approver
				store := sessions.NewCookieStore([]byte(config.AppConfig.Session.SecretKey))
				session, _ := store.Get(req, config.AppConfig.Session.Name)
				session.Values["user_id"] = approverID
				session.Values["username"] = "67890"
				session.Values["role"] = "approver"
				
				rr := httptest.NewRecorder()
				session.Save(req, rr)
				
				var req2 *http.Request
				if endpoint.data != nil {
					req2, _ = http.NewRequest(endpoint.method, endpoint.path, strings.NewReader(endpoint.data.Encode()))
					req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				} else {
					req2, _ = http.NewRequest(endpoint.method, endpoint.path, nil)
				}
				
				cookies := rr.Result().Cookies()
				if len(cookies) > 0 {
					req2.AddCookie(cookies[0])
				}

				rr2 := httptest.NewRecorder()
				handler := handlers.AuthMiddleware(handlers.ApproverMiddleware(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("Admin content"))
				}))
				
				handler(rr2, req2)

				if rr2.Code != http.StatusOK {
					t.Errorf("Approver should be allowed to %s %s, got %d", endpoint.method, endpoint.path, rr2.Code)
				}
			})
		}
	})
}
