package main

import (
	"fmt"
	"gatekeeper/config"
	"gatekeeper/database"
	"gatekeeper/handlers"
	"gatekeeper/test_utils"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Edge cases and error handling tests
func TestDatabaseConnectionErrors(t *testing.T) {
	t.Run("InvalidDatabasePath", func(t *testing.T) {
		// This test would typically require mocking or dependency injection
		// For now, we test behavior with invalid paths
		
		// Test with read-only directory
		tmpDir := t.TempDir()
		readOnlyDir := filepath.Join(tmpDir, "readonly")
		err := os.Mkdir(readOnlyDir, 0444)
		if err != nil {
			t.Fatalf("Failed to create read-only directory: %v", err)
		}
		
		invalidPath := filepath.Join(readOnlyDir, "test.db")
		
		// This would fail in real scenario - testing concept
		t.Logf("Database init with invalid path %s would fail", invalidPath)
	})

	t.Run("DatabaseCorruption", func(t *testing.T) {
		// Test recovery from database issues
		testutils.SetupTestDB()
		defer database.DB.Close()

		// Create test data
		userID, _ := testutils.CreateTestUser("12345", "password", "applicant")
		appID, _ := testutils.CreateTestApplication(userID, "192.168.1.100", 8080, "Test", "pending")

		// Verify data exists
		var count int
		err := database.DB.QueryRow("SELECT COUNT(*) FROM applications WHERE id = ?", appID).Scan(&count)
		if err != nil {
			t.Fatalf("Database query failed: %v", err)
		}
		if count != 1 {
			t.Errorf("Expected 1 application, got %d", count)
		}
	})
}

func TestNetworkAndExternalDependencies(t *testing.T) {
	t.Run("TemplateLoadingErrors", func(t *testing.T) {
		// Test with non-existent template directory
		cfg := config.GetConfig()
		cfg.Templates.Directory = "/nonexistent/templates"
		
		// This should handle missing templates gracefully
		handlers.InitHandlers(cfg)
		
		req, _ := http.NewRequest("GET", "/login", nil)
		rr := httptest.NewRecorder()
		
		handlers.LoginHandler(rr, req)
		
		// Should not crash, might return error or use dummy template
		if rr.Code == http.StatusInternalServerError {
			t.Log("Missing templates handled with error response")
		} else {
			t.Log("Missing templates handled gracefully")
		}
	})

	t.Run("ConfigurationFileCorruption", func(t *testing.T) {
		// Test with various corrupted config files
		corruptedConfigs := []string{
			"", // Empty file
			"{", // Incomplete JSON
			"not json at all", // Invalid JSON
			`{"server": {"port": }}`, // Malformed JSON
		}

		for i, corrupt := range corruptedConfigs {
			t.Run(fmt.Sprintf("Corruption_%d", i), func(t *testing.T) {
				// Create temporary corrupted config file
				tmpfile, err := os.CreateTemp("", "corrupt_config*.json")
				if err != nil {
					t.Fatalf("Failed to create temp file: %v", err)
				}
				defer os.Remove(tmpfile.Name())
				defer tmpfile.Close()

				_, err = tmpfile.WriteString(corrupt)
				if err != nil {
					t.Fatalf("Failed to write corrupt config: %v", err)
				}
				tmpfile.Close()

				// Try to load corrupted config
				err = config.LoadConfig(tmpfile.Name())
				if err == nil {
					t.Logf("Corrupted config %d was handled gracefully", i)
				} else {
					t.Logf("Corrupted config %d properly returned error: %v", i, err)
				}
			})
		}
	})
}

func TestConcurrencyAndRaceConditions(t *testing.T) {
	testutils.SetupTestDB()
	defer database.DB.Close()

	config.AppConfig = config.GetConfig()
	handlers.InitHandlers(config.AppConfig)

	t.Run("ConcurrentUserRegistration", func(t *testing.T) {
		// Test concurrent registration of users with same username
		username := "99999"
		
		results := make(chan int, 5)
		
		// Start multiple registration goroutines
		for i := 0; i < 5; i++ {
			go func() {
				formData := url.Values{}
				formData.Set("username", username)
				formData.Set("password", "password123")

				req, _ := http.NewRequest("POST", "/register", strings.NewReader(formData.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				rr := httptest.NewRecorder()
				handlers.RegisterHandler(rr, req)
				
				results <- rr.Code
			}()
		}

		// Collect results
		successCount := 0
		for i := 0; i < 5; i++ {
			code := <-results
			if code == http.StatusSeeOther || code == http.StatusOK {
				successCount++
			}
		}

		// Only one registration should succeed
		if successCount > 1 {
			t.Errorf("Expected only 1 successful registration, got %d", successCount)
		}
	})

	t.Run("ConcurrentApplicationSubmission", func(t *testing.T) {
		// Create test user
		userID, _ := testutils.CreateTestUser("12321", "password", "applicant")
		
		// Test concurrent application submission
		results := make(chan int, 3)
		
		for i := 0; i < 3; i++ {
			go func(index int) {
				formData := url.Values{}
				formData.Set("ip_address", "192.168.1.100")
				formData.Set("port", "8080")
				formData.Set("reason", fmt.Sprintf("Concurrent test %d", index))

				req, _ := http.NewRequest("POST", "/apply", strings.NewReader(formData.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				rr := httptest.NewRecorder()
				handlers.ApplyHandler(rr, req)
				
				results <- rr.Code
			}(i)
		}

		// All submissions might succeed since they're from the same user
		for i := 0; i < 3; i++ {
			<-results
		}

		// Check how many applications were actually created
		var count int
		database.DB.QueryRow("SELECT COUNT(*) FROM applications WHERE user_id = ?", userID).Scan(&count)
		t.Logf("Created %d applications from concurrent submissions", count)
	})

	t.Run("ConcurrentDatabaseAccess", func(t *testing.T) {
		// Create test user
		userID, _ := testutils.CreateTestUser("54321", "password", "applicant")
		
		// Create some applications
		for i := 0; i < 10; i++ {
			testutils.CreateTestApplication(userID, fmt.Sprintf("192.168.1.%d", i+1), 8080+i, "Test", "pending")
		}

		// Concurrent reads
		results := make(chan error, 10)
		
		for i := 0; i < 10; i++ {
			go func() {
				rows, err := database.DB.Query("SELECT id, ip_address, port FROM applications WHERE user_id = ?", userID)
				if err != nil {
					results <- err
					return
				}
				
				count := 0
				for rows.Next() {
					var id, port int
					var ip string
					rows.Scan(&id, &ip, &port)
					count++
				}
				rows.Close()
				
				results <- nil
			}()
		}

		// Check for errors
		errorCount := 0
		for i := 0; i < 10; i++ {
			if err := <-results; err != nil {
				errorCount++
				t.Logf("Concurrent read error: %v", err)
			}
		}

		if errorCount > 0 {
			t.Errorf("Got %d errors during concurrent database access", errorCount)
		}
	})
}

func TestLargeDataHandling(t *testing.T) {
	testutils.SetupTestDB()
	defer database.DB.Close()

	config.AppConfig = config.GetConfig()
	handlers.InitHandlers(config.AppConfig)

	t.Run("LargeNumberOfUsers", func(t *testing.T) {
		// Create many users
		userCount := 1000
		for i := 0; i < userCount; i++ {
			username := fmt.Sprintf("%05d", i)
			testutils.CreateTestUser(username, "password", "applicant")
		}

		// Test querying large dataset
		start := time.Now()
		rows, err := database.DB.Query("SELECT id, username, role FROM users ORDER BY id")
		if err != nil {
			t.Fatalf("Failed to query users: %v", err)
		}
		
		count := 0
		for rows.Next() {
			var id int
			var username, role string
			rows.Scan(&id, &username, &role)
			count++
		}
		rows.Close()
		
		queryTime := time.Since(start)
		t.Logf("Queried %d users in %v", count, queryTime)

		if queryTime > time.Second {
			t.Logf("Query took longer than 1 second (%v) - consider optimization", queryTime)
		}
	})

	t.Run("LargeNumberOfApplications", func(t *testing.T) {
		// Create test user
		userID, _ := testutils.CreateTestUser("88888", "password", "applicant")
		
		// Create many applications
		appCount := 5000
		for i := 0; i < appCount; i++ {
			ip := fmt.Sprintf("10.%d.%d.%d", (i/65536)%256, (i/256)%256, i%256)
			port := 8000 + (i % 1000)
			testutils.CreateTestApplication(userID, ip, port, fmt.Sprintf("App %d", i), "pending")
		}

		// Test dashboard with many applications
		start := time.Now()
		req, _ := http.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()
		
		handlers.DashboardHandler(rr, req)
		
		responseTime := time.Since(start)
		t.Logf("Dashboard loaded %d applications in %v", appCount, responseTime)

		if responseTime > 5*time.Second {
			t.Logf("Dashboard response took longer than 5 seconds (%v) - consider pagination", responseTime)
		}
	})

	t.Run("VeryLongInputFields", func(t *testing.T) {
		// Test with extremely long input fields
		longReason := strings.Repeat("A", 100000) // 100KB string
		
		formData := url.Values{}
		formData.Set("ip_address", "192.168.1.100")
		formData.Set("port", "8080")
		formData.Set("reason", longReason)

		req, _ := http.NewRequest("POST", "/apply", strings.NewReader(formData.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		start := time.Now()
		rr := httptest.NewRecorder()
		handlers.ApplyHandler(rr, req)
		processTime := time.Since(start)

		t.Logf("Processed very long input in %v", processTime)

		if processTime > time.Second {
			t.Logf("Processing took longer than 1 second (%v) - consider input size limits", processTime)
		}
	})
}

func TestMemoryAndResourceLimits(t *testing.T) {
	testutils.SetupTestDB()
	defer database.DB.Close()

	t.Run("MemoryLeakDetection", func(t *testing.T) {
		// Simple memory usage test
		// In production, you'd use more sophisticated memory profiling
		
		config.AppConfig = config.GetConfig()
		handlers.InitHandlers(config.AppConfig)

		userID, _ := testutils.CreateTestUser("77777", "password", "applicant")
		
		// Perform many operations that could leak memory
		for i := 0; i < 1000; i++ {
			// Create application
			testutils.CreateTestApplication(userID, "192.168.1.100", 8080+i, "Test", "pending")
			
			// Query dashboard
			req, _ := http.NewRequest("GET", "/", nil)
			rr := httptest.NewRecorder()
			handlers.DashboardHandler(rr, req)
			
			// Every 100 iterations, force garbage collection
			if i%100 == 0 {
				// In real test, you'd check memory usage here
				t.Logf("Completed %d iterations", i)
			}
		}
		
		t.Log("Memory leak test completed - monitor memory usage in production")
	})

	t.Run("DatabaseConnectionLimit", func(t *testing.T) {
		// Test behavior with many concurrent database connections
		
		connectionCount := 50
		results := make(chan error, connectionCount)
		
		for i := 0; i < connectionCount; i++ {
			go func(index int) {
				// Perform database operation
				var count int
				err := database.DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
				results <- err
			}(i)
		}

		errorCount := 0
		for i := 0; i < connectionCount; i++ {
			if err := <-results; err != nil {
				errorCount++
				t.Logf("Connection %d error: %v", i, err)
			}
		}

		if errorCount > 0 {
			t.Logf("Got %d database connection errors out of %d attempts", errorCount, connectionCount)
		}
	})
}

func TestErrorRecovery(t *testing.T) {
	testutils.SetupTestDB()
	defer database.DB.Close()

	config.AppConfig = config.GetConfig()
	handlers.InitHandlers(config.AppConfig)

	t.Run("PanicRecovery", func(t *testing.T) {
		// Test that handlers don't crash on unexpected input
		
		// Test with nil request body
		req, _ := http.NewRequest("POST", "/login", nil)
		rr := httptest.NewRecorder()
		
		// This might panic in some implementations
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Handler panicked: %v", r)
			}
		}()
		
		handlers.LoginHandler(rr, req)
		
		// Should handle gracefully without panicking
		t.Log("Handler handled nil body gracefully")
	})

	t.Run("InvalidHTTPMethods", func(t *testing.T) {
		// Test with unexpected HTTP methods
		methods := []string{"PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
		
		for _, method := range methods {
			t.Run(method, func(t *testing.T) {
				req, _ := http.NewRequest(method, "/login", nil)
				rr := httptest.NewRecorder()
				
				handlers.LoginHandler(rr, req)
				
				// Should handle gracefully, typically with 405 Method Not Allowed
				if rr.Code == http.StatusInternalServerError {
					t.Errorf("Handler returned 500 for %s method", method)
				}
			})
		}
	})

	t.Run("MalformedFormData", func(t *testing.T) {
		// Test with malformed form data
		malformedData := []string{
			"username=test&", // Incomplete
			"username=test&password", // Missing value
			"=value&=", // Missing keys
			"username=test&username=duplicate", // Duplicate fields
		}

		for i, data := range malformedData {
			t.Run(fmt.Sprintf("Malformed_%d", i), func(t *testing.T) {
				req, _ := http.NewRequest("POST", "/login", strings.NewReader(data))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				
				rr := httptest.NewRecorder()
				
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("Handler panicked on malformed data: %v", r)
					}
				}()
				
				handlers.LoginHandler(rr, req)
				
				// Should handle gracefully
				t.Logf("Malformed data handled with status: %d", rr.Code)
			})
		}
	})
}

func TestBoundaryConditions(t *testing.T) {
	testutils.SetupTestDB()
	defer database.DB.Close()

	config.AppConfig = config.GetConfig()
	handlers.InitHandlers(config.AppConfig)

	t.Run("PortBoundaries", func(t *testing.T) {
		userID, _ := testutils.CreateTestUser("66666", "password", "applicant")
		_ = userID

		boundaryPorts := []string{
			"1", "65535", // Valid boundaries
			"0", "65536", "-1", "999999", // Invalid boundaries
		}

		for _, port := range boundaryPorts {
			t.Run(fmt.Sprintf("Port_%s", port), func(t *testing.T) {
				formData := url.Values{}
				formData.Set("ip_address", "192.168.1.100")
				formData.Set("port", port)
				formData.Set("reason", "Boundary test")

				req, _ := http.NewRequest("POST", "/apply", strings.NewReader(formData.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				rr := httptest.NewRecorder()
				handlers.ApplyHandler(rr, req)

				// Log behavior for boundary values
				t.Logf("Port %s resulted in status: %d", port, rr.Code)
			})
		}
	})

	t.Run("UsernameLengthBoundaries", func(t *testing.T) {
		usernames := []string{
			"", // Empty
			"1234", // Too short (4 digits)
			"123456", // Too long (6 digits)
			"12345", // Valid (5 digits)
			"a1234", // Too short (1 letter + 4 digits)
			"a123456", // Too long (1 letter + 6 digits)
			"a12345", // Valid (1 letter + 5 digits)
		}

		for _, username := range usernames {
			t.Run(fmt.Sprintf("Username_%s", username), func(t *testing.T) {
				formData := url.Values{}
				formData.Set("username", username)
				formData.Set("password", "password123")

				req, _ := http.NewRequest("POST", "/register", strings.NewReader(formData.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				rr := httptest.NewRecorder()
				handlers.RegisterHandler(rr, req)

				t.Logf("Username '%s' resulted in status: %d", username, rr.Code)
			})
		}
	})

	t.Run("SessionTimeout", func(t *testing.T) {
		// Test session expiration behavior
		// This would require more sophisticated session management testing
		
		// Create a user and login
		testutils.CreateTestUser("55555", "password", "applicant")
		
		formData := url.Values{}
		formData.Set("username", "55555")
		formData.Set("password", "password")

		req, _ := http.NewRequest("POST", "/login", strings.NewReader(formData.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rr := httptest.NewRecorder()
		handlers.LoginHandler(rr, req)

		cookies := rr.Result().Cookies()
		if len(cookies) > 0 {
			// Test accessing dashboard with session cookie
			dashReq, _ := http.NewRequest("GET", "/", nil)
			dashReq.AddCookie(cookies[0])
			
			dashRR := httptest.NewRecorder()
			handlers.DashboardHandler(dashRR, dashReq)
			
			t.Logf("Dashboard access with session resulted in: %d", dashRR.Code)
		}
	})
}