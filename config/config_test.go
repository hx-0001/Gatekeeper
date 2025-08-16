package config

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig_FileNotExists(t *testing.T) {
	// Test loading config when file doesn't exist
	err := LoadConfig("nonexistent.json")
	if err != nil {
		t.Errorf("Expected no error when config file doesn't exist, got: %v", err)
	}

	// Should have default configuration
	if AppConfig == nil {
		t.Error("AppConfig should not be nil after loading defaults")
	}

	// Verify some default values
	if AppConfig.Server.Port != ":58080" {
		t.Errorf("Expected default port :58080, got: %s", AppConfig.Server.Port)
	}
	if AppConfig.Database.Driver != "sqlite3" {
		t.Errorf("Expected default driver sqlite3, got: %s", AppConfig.Database.Driver)
	}
}

func TestLoadConfig_ValidFile(t *testing.T) {
	// Create a temporary config file
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "test_config.json")

	testConfig := &Config{
		Server: ServerConfig{
			Port:      ":9090",
			StaticDir: "custom_static",
			LogLevel:  "debug",
		},
		Database: DatabaseConfig{
			Path:   "./test.db",
			Driver: "sqlite3",
		},
		Session: SessionConfig{
			SecretKey: "test-secret",
			Name:      "test-session",
			MaxAge:    3600,
		},
		Templates: TemplatesConfig{
			Directory: "test_templates",
			Pattern:   "*.tmpl",
		},
		Admin: AdminConfig{
			Username: "testadmin",
			Password: "testpass",
			Role:     "approver",
		},
		Security: SecurityConfig{
			UsernamePattern: `^test\d+$`,
			AllowedRoles:    []string{"user", "admin"},
			BcryptCost:      10,
		},
		Expiration: ExpirationConfig{
			CleanupInterval: 10,
			Enabled:         false,
		},
	}

	// Write test config to file
	data, err := json.MarshalIndent(testConfig, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal test config: %v", err)
	}

	err = ioutil.WriteFile(configPath, data, 0644)
	if err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}

	// Load the config
	err = LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify loaded values
	if AppConfig.Server.Port != ":9090" {
		t.Errorf("Expected port :9090, got: %s", AppConfig.Server.Port)
	}
	if AppConfig.Session.SecretKey != "test-secret" {
		t.Errorf("Expected secret key test-secret, got: %s", AppConfig.Session.SecretKey)
	}
	if AppConfig.Security.BcryptCost != 10 {
		t.Errorf("Expected bcrypt cost 10, got: %d", AppConfig.Security.BcryptCost)
	}
	if AppConfig.Expiration.Enabled != false {
		t.Errorf("Expected expiration enabled false, got: %t", AppConfig.Expiration.Enabled)
	}
}

func TestLoadConfig_InvalidJSON(t *testing.T) {
	// Create a file with invalid JSON
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "invalid.json")
	
	err := ioutil.WriteFile(configPath, []byte("invalid json content"), 0644)
	if err != nil {
		t.Fatalf("Failed to write invalid JSON file: %v", err)
	}

	// Should return error for invalid JSON
	err = LoadConfig(configPath)
	if err == nil {
		t.Error("Expected error when loading invalid JSON, got nil")
	}
}

func TestLoadConfig_ReadError(t *testing.T) {
	// Create a directory instead of a file to cause read error
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config_dir")
	
	err := os.Mkdir(configPath, 0755)
	if err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}

	// Should return error when trying to read directory as file
	err = LoadConfig(configPath)
	if err == nil {
		t.Error("Expected error when loading directory as config file, got nil")
	}
}

func TestGetDefaultConfig(t *testing.T) {
	config := getDefaultConfig()
	
	// Test all default values
	if config.Server.Port != ":58080" {
		t.Errorf("Expected default port :58080, got: %s", config.Server.Port)
	}
	if config.Server.StaticDir != "static" {
		t.Errorf("Expected default static dir 'static', got: %s", config.Server.StaticDir)
	}
	if config.Server.LogLevel != "info" {
		t.Errorf("Expected default log level 'info', got: %s", config.Server.LogLevel)
	}
	
	if config.Database.Path != "./gatekeeper.db" {
		t.Errorf("Expected default db path './gatekeeper.db', got: %s", config.Database.Path)
	}
	if config.Database.Driver != "sqlite3" {
		t.Errorf("Expected default driver 'sqlite3', got: %s", config.Database.Driver)
	}
	
	if config.Session.SecretKey != "something-very-secret" {
		t.Errorf("Expected default secret key, got: %s", config.Session.SecretKey)
	}
	if config.Session.MaxAge != 86400 {
		t.Errorf("Expected default max age 86400, got: %d", config.Session.MaxAge)
	}
	
	if config.Admin.Username != "admin" {
		t.Errorf("Expected default admin username 'admin', got: %s", config.Admin.Username)
	}
	if config.Admin.Role != "approver" {
		t.Errorf("Expected default admin role 'approver', got: %s", config.Admin.Role)
	}
	
	if config.Security.BcryptCost != 12 {
		t.Errorf("Expected default bcrypt cost 12, got: %d", config.Security.BcryptCost)
	}
	if len(config.Security.AllowedRoles) != 2 {
		t.Errorf("Expected 2 default allowed roles, got: %d", len(config.Security.AllowedRoles))
	}
	
	if config.Expiration.CleanupInterval != 5 {
		t.Errorf("Expected default cleanup interval 5, got: %d", config.Expiration.CleanupInterval)
	}
	if config.Expiration.Enabled != true {
		t.Errorf("Expected default expiration enabled true, got: %t", config.Expiration.Enabled)
	}
}

func TestValidateAndSetDefaults(t *testing.T) {
	// Test with partial config that needs defaults
	partialConfig := &Config{
		Server: ServerConfig{
			Port: ":8080", // Only set port
		},
		Database: DatabaseConfig{
			Path: "./custom.db", // Only set path
		},
		Security: SecurityConfig{
			BcryptCost: 8, // Only set bcrypt cost
		},
	}
	
	validateAndSetDefaults(partialConfig)
	
	// Check that defaults were applied for missing fields
	if partialConfig.Server.StaticDir != "static" {
		t.Errorf("Expected default static dir to be set, got: %s", partialConfig.Server.StaticDir)
	}
	if partialConfig.Database.Driver != "sqlite3" {
		t.Errorf("Expected default driver to be set, got: %s", partialConfig.Database.Driver)
	}
	if partialConfig.Session.SecretKey != "something-very-secret" {
		t.Errorf("Expected default secret key to be set, got: %s", partialConfig.Session.SecretKey)
	}
	
	// Check that explicitly set values were preserved
	if partialConfig.Server.Port != ":8080" {
		t.Errorf("Expected custom port to be preserved, got: %s", partialConfig.Server.Port)
	}
	if partialConfig.Database.Path != "./custom.db" {
		t.Errorf("Expected custom db path to be preserved, got: %s", partialConfig.Database.Path)
	}
	if partialConfig.Security.BcryptCost != 8 {
		t.Errorf("Expected custom bcrypt cost to be preserved, got: %d", partialConfig.Security.BcryptCost)
	}
}

func TestSaveConfig(t *testing.T) {
	// Set up a test config
	testConfig := getDefaultConfig()
	testConfig.Server.Port = ":9999"
	AppConfig = testConfig
	
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "saved_config.json")
	
	err := SaveConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to save config: %v", err)
	}
	
	// Verify file was created and contains expected content
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		t.Fatalf("Failed to read saved config: %v", err)
	}
	
	var loadedConfig Config
	err = json.Unmarshal(data, &loadedConfig)
	if err != nil {
		t.Fatalf("Failed to unmarshal saved config: %v", err)
	}
	
	if loadedConfig.Server.Port != ":9999" {
		t.Errorf("Expected saved port :9999, got: %s", loadedConfig.Server.Port)
	}
}

func TestSaveConfig_NilConfig(t *testing.T) {
	// Test saving when AppConfig is nil
	AppConfig = nil
	
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "nil_config.json")
	
	err := SaveConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to save config when AppConfig is nil: %v", err)
	}
	
	// Should have saved default config
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		t.Fatalf("Failed to read saved config: %v", err)
	}
	
	var loadedConfig Config
	err = json.Unmarshal(data, &loadedConfig)
	if err != nil {
		t.Fatalf("Failed to unmarshal saved config: %v", err)
	}
	
	if loadedConfig.Server.Port != ":58080" {
		t.Errorf("Expected default port when saving nil config, got: %s", loadedConfig.Server.Port)
	}
}

func TestSaveConfig_WriteError(t *testing.T) {
	// Try to save to a read-only directory
	tempDir := t.TempDir()
	readOnlyDir := filepath.Join(tempDir, "readonly")
	err := os.Mkdir(readOnlyDir, 0444) // Read-only permissions
	if err != nil {
		t.Fatalf("Failed to create read-only directory: %v", err)
	}
	
	configPath := filepath.Join(readOnlyDir, "config.json")
	
	AppConfig = getDefaultConfig()
	err = SaveConfig(configPath)
	if err == nil {
		t.Error("Expected error when saving to read-only directory, got nil")
	}
}

func TestGetConfig(t *testing.T) {
	// Test when AppConfig is nil
	AppConfig = nil
	config := GetConfig()
	
	if config == nil {
		t.Error("GetConfig should never return nil")
	}
	
	// Should return default config
	if config.Server.Port != ":58080" {
		t.Errorf("Expected default port, got: %s", config.Server.Port)
	}
	
	// Test when AppConfig is already set
	customConfig := getDefaultConfig()
	customConfig.Server.Port = ":7777"
	AppConfig = customConfig
	
	config = GetConfig()
	if config.Server.Port != ":7777" {
		t.Errorf("Expected existing config port :7777, got: %s", config.Server.Port)
	}
}

func TestConfigStructCompleteness(t *testing.T) {
	// Ensure all config struct fields have corresponding defaults
	config := getDefaultConfig()
	
	// Test that no fields are empty/zero values
	if config.Server.Port == "" {
		t.Error("Server.Port should have default value")
	}
	if config.Server.StaticDir == "" {
		t.Error("Server.StaticDir should have default value")
	}
	if config.Server.LogLevel == "" {
		t.Error("Server.LogLevel should have default value")
	}
	
	if config.Database.Path == "" {
		t.Error("Database.Path should have default value")
	}
	if config.Database.Driver == "" {
		t.Error("Database.Driver should have default value")
	}
	
	if config.Session.SecretKey == "" {
		t.Error("Session.SecretKey should have default value")
	}
	if config.Session.Name == "" {
		t.Error("Session.Name should have default value")
	}
	if config.Session.MaxAge == 0 {
		t.Error("Session.MaxAge should have default value")
	}
	
	if config.Templates.Directory == "" {
		t.Error("Templates.Directory should have default value")
	}
	if config.Templates.Pattern == "" {
		t.Error("Templates.Pattern should have default value")
	}
	
	if config.Admin.Username == "" {
		t.Error("Admin.Username should have default value")
	}
	if config.Admin.Password == "" {
		t.Error("Admin.Password should have default value")
	}
	if config.Admin.Role == "" {
		t.Error("Admin.Role should have default value")
	}
	
	if config.Security.UsernamePattern == "" {
		t.Error("Security.UsernamePattern should have default value")
	}
	if len(config.Security.AllowedRoles) == 0 {
		t.Error("Security.AllowedRoles should have default values")
	}
	if config.Security.BcryptCost == 0 {
		t.Error("Security.BcryptCost should have default value")
	}
	
	if config.Expiration.CleanupInterval == 0 {
		t.Error("Expiration.CleanupInterval should have default value")
	}
}

// Reset AppConfig after each test to avoid interference
func TestMain(m *testing.M) {
	// Run tests
	code := m.Run()
	
	// Reset global state
	AppConfig = nil
	
	os.Exit(code)
}