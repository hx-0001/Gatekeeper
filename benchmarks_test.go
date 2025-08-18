package main

import (
	"database/sql"
	"embed"
	"fmt"
	"gatekeeper/config"
	"gatekeeper/database"
	"gatekeeper/handlers"
	"gatekeeper/test_utils"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func BenchmarkBcryptHashing(b *testing.B) {
	password := "testpassword123"
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkBcryptHashingDifferentCosts(b *testing.B) {
	password := "testpassword123"
	costs := []int{4, 8, 10, 12, 14}
	
	for _, cost := range costs {
		b.Run(fmt.Sprintf("Cost%d", cost), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := bcrypt.GenerateFromPassword([]byte(password), cost)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkBcryptVerification(b *testing.B) {
	password := "testpassword123"
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		b.Fatal(err)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := bcrypt.CompareHashAndPassword(hash, []byte(password))
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDatabaseUserInsert(b *testing.B) {
	// Setup test database
	testutils.SetupTestDB()
	defer database.DB.Close()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		username := fmt.Sprintf("user%d", i)
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
		
		_, err := database.DB.Exec("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
			username, string(hashedPassword), "applicant")
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDatabaseUserQuery(b *testing.B) {
	// Setup test database with test data
	testutils.SetupTestDB()
	defer database.DB.Close()
	
	// Insert some test users
	for i := 0; i < 100; i++ {
		username := fmt.Sprintf("user%d", i)
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
		database.DB.Exec("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
			username, string(hashedPassword), "applicant")
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		username := fmt.Sprintf("user%d", i%100)
		var user struct {
			ID       int
			Username string
			Password string
			Role     string
		}
		err := database.DB.QueryRow("SELECT id, username, password, role FROM users WHERE username = ?", username).
			Scan(&user.ID, &user.Username, &user.Password, &user.Role)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkApplicationInsert(b *testing.B) {
	// Setup test database
	testutils.SetupTestDB()
	defer database.DB.Close()
	
	// Create a test user
	userID, err := testutils.CreateTestUser("黄希12421", "password", "applicant")
	if err != nil {
		b.Fatal(err)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ipAddress := fmt.Sprintf("192.168.1.%d", i%254+1)
		port := 8000 + (i % 1000)
		reason := fmt.Sprintf("Test application %d", i)
		
		_, err := database.DB.Exec(`
			INSERT INTO applications (user_id, ip_address, port, reason, status, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			userID, ipAddress, port, reason, "pending", time.Now(), time.Now())
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkApplicationQuery(b *testing.B) {
	// Setup test database with test data
	testutils.SetupTestDB()
	defer database.DB.Close()
	
	userID, _ := testutils.CreateTestUser("黄希12421", "password", "applicant")
	
	// Insert test applications
	for i := 0; i < 100; i++ {
		ipAddress := fmt.Sprintf("192.168.1.%d", i%254+1)
		port := 8000 + i
		testutils.CreateTestApplication(userID, ipAddress, port, "Test app", "pending")
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rows, err := database.DB.Query(`
			SELECT id, ip_address, port, reason, status, created_at
			FROM applications WHERE user_id = ? ORDER BY created_at DESC`, userID)
		if err != nil {
			b.Fatal(err)
		}
		
		count := 0
		for rows.Next() {
			var app struct {
				ID        int
				IPAddress string
				Port      int
				Reason    string
				Status    string
				CreatedAt time.Time
			}
			err := rows.Scan(&app.ID, &app.IPAddress, &app.Port, &app.Reason, &app.Status, &app.CreatedAt)
			if err != nil {
				rows.Close()
				b.Fatal(err)
			}
			count++
		}
		rows.Close()
	}
}

func BenchmarkLoginHandler(b *testing.B) {
	// Setup test environment
	testutils.SetupTestDB()
	defer database.DB.Close()
	
	config.AppConfig = config.GetConfig()
	handlers.InitHandlers(config.AppConfig, embed.FS{})
	
	// Create test user
	testutils.CreateTestUser("黄希12421", "password123", "applicant")
	
	// Prepare form data
	formData := url.Values{}
	formData.Set("username", "黄希12421")
	formData.Set("password", "password123")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, err := http.NewRequest("POST", "/login", strings.NewReader(formData.Encode()))
		if err != nil {
			b.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		
		rr := httptest.NewRecorder()
		handlers.LoginHandler(rr, req)
		
		if rr.Code != http.StatusSeeOther && rr.Code != http.StatusOK {
			b.Fatalf("Expected status %d or %d, got %d", http.StatusSeeOther, http.StatusOK, rr.Code)
		}
	}
}

func BenchmarkRegisterHandler(b *testing.B) {
	// Setup test environment
	testutils.SetupTestDB()
	defer database.DB.Close()
	
	config.AppConfig = config.GetConfig()
	handlers.InitHandlers(config.AppConfig, embed.FS{})
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Use unique usernames for each iteration
		username := fmt.Sprintf("%05d", i)
		
		formData := url.Values{}
		formData.Set("username", username)
		formData.Set("password", "password123")
		
		req, err := http.NewRequest("POST", "/register", strings.NewReader(formData.Encode()))
		if err != nil {
			b.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		
		rr := httptest.NewRecorder()
		handlers.RegisterHandler(rr, req)
		
		if rr.Code != http.StatusSeeOther && rr.Code != http.StatusOK {
			b.Fatalf("Expected status %d or %d, got %d", http.StatusSeeOther, http.StatusOK, rr.Code)
		}
	}
}

func BenchmarkDashboardHandler(b *testing.B) {
	// Setup test environment
	testutils.SetupTestDB()
	defer database.DB.Close()
	
	config.AppConfig = config.GetConfig()
	handlers.InitHandlers(config.AppConfig, embed.FS{})
	
	// Create test user and applications
	userID, _ := testutils.CreateTestUser("黄希12421", "password", "applicant")
	for i := 0; i < 10; i++ {
		ipAddress := fmt.Sprintf("192.168.1.%d", i+1)
		testutils.CreateTestApplication(userID, ipAddress, 8080+i, "Test app", "pending")
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, err := http.NewRequest("GET", "/", nil)
		if err != nil {
			b.Fatal(err)
		}
		
		rr := httptest.NewRecorder()
		handlers.DashboardHandler(rr, req)
		
		if rr.Code != http.StatusOK {
			b.Fatalf("Expected status %d, got %d", http.StatusOK, rr.Code)
		}
	}
}

func BenchmarkConfigLoading(b *testing.B) {
	// Create a test config file
	configContent := `{
		"server": {
			"port": ":8080",
			"static_dir": "static",
			"log_level": "info"
		},
		"database": {
			"path": "./test.db",
			"driver": "sqlite3"
		},
		"session": {
			"secret_key": "test-secret",
			"name": "session",
			"max_age": 3600
		},
		"templates": {
			"directory": "templates",
			"pattern": "*.html"
		},
		"admin": {
			"username": "admin",
			"password": "admin",
			"role": "approver"
		},
		"security": {
			"username_pattern": "^([a-z]\\d{5}|\\d{5})$",
			"allowed_roles": ["applicant", "approver"],
			"bcrypt_cost": 12
		},
		"expiration": {
			"cleanup_interval_minutes": 5,
			"enabled": true
		}
	}`
	
	// Write to temporary file
	tmpfile, err := ioutil.TempFile("", "config*.json")
	if err != nil {
		b.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())
	defer tmpfile.Close()
	
	_, err = tmpfile.WriteString(configContent)
	if err != nil {
		b.Fatal(err)
	}
	tmpfile.Close()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := config.LoadConfig(tmpfile.Name())
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSessionOperations(b *testing.B) {
	config.AppConfig = config.GetConfig()
	handlers.InitHandlers(config.AppConfig, embed.FS{})
	
	b.Run("SessionCreation", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			rr := httptest.NewRecorder()
			
			// Simulate session creation (this happens in login)
			formData := url.Values{}
			formData.Set("username", "admin")
			formData.Set("password", "admin")
			
			loginReq, _ := http.NewRequest("POST", "/login", strings.NewReader(formData.Encode()))
			loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			
			handlers.LoginHandler(rr, loginReq)
		}
	})
	
	b.Run("SessionReading", func(b *testing.B) {
		// Create a request with session cookies
		rr := httptest.NewRecorder()
		
		// First, create a session
		formData := url.Values{}
		formData.Set("username", "admin")
		formData.Set("password", "admin")
		
		loginReq, _ := http.NewRequest("POST", "/login", strings.NewReader(formData.Encode()))
		loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		loginRR := httptest.NewRecorder()
		handlers.LoginHandler(loginRR, loginReq)
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			dashReq, _ := http.NewRequest("GET", "/", nil)
			// Extract cookies from login response
			if len(loginRR.Result().Cookies()) > 0 {
				dashReq.AddCookie(loginRR.Result().Cookies()[0])
			}
			handlers.DashboardHandler(rr, dashReq)
		}
	})
}

func BenchmarkConcurrentUserRegistration(b *testing.B) {
	testutils.SetupTestDB()
	defer database.DB.Close()
	
	config.AppConfig = config.GetConfig()
	handlers.InitHandlers(config.AppConfig, embed.FS{})
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			username := fmt.Sprintf("user%d_%d", b.N, i)
			i++
			
			formData := url.Values{}
			formData.Set("username", username)
			formData.Set("password", "password123")
			
			req, err := http.NewRequest("POST", "/register", strings.NewReader(formData.Encode()))
			if err != nil {
				b.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			
			rr := httptest.NewRecorder()
			handlers.RegisterHandler(rr, req)
		}
	})
}

func BenchmarkConcurrentDatabaseQueries(b *testing.B) {
	testutils.SetupTestDB()
	defer database.DB.Close()
	
	// Insert test data
	for i := 0; i < 100; i++ {
		username := fmt.Sprintf("user%d", i)
		testutils.CreateTestUser(username, "password", "applicant")
	}
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			username := fmt.Sprintf("user%d", i%100)
			i++
			
			var user struct {
				ID       int
				Username string
				Role     string
			}
			err := database.DB.QueryRow("SELECT id, username, role FROM users WHERE username = ?", username).
				Scan(&user.ID, &user.Username, &user.Role)
			if err != nil && err != sql.ErrNoRows {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkLargeApplicationsList(b *testing.B) {
	testutils.SetupTestDB()
	defer database.DB.Close()
	
	// Create test user
	userID, _ := testutils.CreateTestUser("黄希12421", "password", "applicant")
	
	// Insert many applications
	applicationCounts := []int{10, 100, 1000, 5000}
	
	for _, count := range applicationCounts {
		b.Run(fmt.Sprintf("Apps%d", count), func(b *testing.B) {
			// Clean applications table
			database.DB.Exec("DELETE FROM applications")
			
			// Insert applications
			for i := 0; i < count; i++ {
				ipAddress := fmt.Sprintf("192.168.%d.%d", i/254+1, i%254+1)
				port := 8000 + (i % 1000)
				testutils.CreateTestApplication(userID, ipAddress, port, fmt.Sprintf("App %d", i), "pending")
			}
			
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				rows, err := database.DB.Query(`
					SELECT id, ip_address, port, reason, status, created_at
					FROM applications WHERE user_id = ? ORDER BY created_at DESC`, userID)
				if err != nil {
					b.Fatal(err)
				}
				
				count := 0
				for rows.Next() {
					var app struct {
						ID        int
						IPAddress string
						Port      int
						Reason    string
						Status    string
						CreatedAt time.Time
					}
					rows.Scan(&app.ID, &app.IPAddress, &app.Port, &app.Reason, &app.Status, &app.CreatedAt)
					count++
				}
				rows.Close()
			}
		})
	}
}

func BenchmarkMemoryUsage(b *testing.B) {
	testutils.SetupTestDB()
	defer database.DB.Close()
	
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		// Create user
		username := fmt.Sprintf("user%d", i)
		userID, _ := testutils.CreateTestUser(username, "password", "applicant")
		
		// Create applications
		for j := 0; j < 10; j++ {
			ipAddress := fmt.Sprintf("192.168.%d.%d", i%255, j%255)
			testutils.CreateTestApplication(userID, ipAddress, 8080+j, "Test app", "pending")
		}
		
		// Query applications
		rows, _ := database.DB.Query("SELECT * FROM applications WHERE user_id = ?", userID)
		for rows.Next() {
			// Just iterate, don't store
		}
		rows.Close()
	}
}

