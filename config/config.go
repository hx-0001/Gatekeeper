package config

import (
	"encoding/json"
	"fmt"
	"gatekeeper/logger"
	"io/ioutil"
	"os"
)

// Config represents the application configuration
type Config struct {
	Server     ServerConfig     `json:"server"`
	Database   DatabaseConfig   `json:"database"`
	Session    SessionConfig    `json:"session"`
	Templates  TemplatesConfig  `json:"templates"`
	Admin      AdminConfig      `json:"admin"`
	Security   SecurityConfig   `json:"security"`
	Expiration ExpirationConfig `json:"expiration"`
}

// ServerConfig contains server-related configuration
type ServerConfig struct {
	Port       string `json:"port"`
	StaticDir  string `json:"static_dir"`
	LogLevel   string `json:"log_level"`
	UseEmbedded bool  `json:"use_embedded"`
}

// DatabaseConfig contains database-related configuration
type DatabaseConfig struct {
	Path   string `json:"path"`
	Driver string `json:"driver"`
}

// SessionConfig contains session-related configuration
type SessionConfig struct {
	SecretKey string `json:"secret_key"`
	Name      string `json:"name"`
	MaxAge    int    `json:"max_age"`
}

// TemplatesConfig contains template-related configuration
type TemplatesConfig struct {
	Directory string `json:"directory"`
	Pattern   string `json:"pattern"`
	UseEmbedded bool `json:"use_embedded"`
}

// AdminConfig contains default admin user configuration
type AdminConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

// SecurityConfig contains security-related configuration
type SecurityConfig struct {
	UsernamePattern string   `json:"username_pattern"`
	AllowedRoles    []string `json:"allowed_roles"`
	BcryptCost      int      `json:"bcrypt_cost"`
}

// ExpirationConfig contains expiration cleanup configuration
type ExpirationConfig struct {
	CleanupInterval int  `json:"cleanup_interval_minutes"`
	Enabled         bool `json:"enabled"`
}

var AppConfig *Config

// LoadConfig loads configuration from a JSON file
func LoadConfig(configPath string) error {
	// Set default config if file doesn't exist
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		logger.LogAtLevel("info", "info", "INFO: Config file %s not found, using defaults", configPath)
		AppConfig = getDefaultConfig()
		return nil
	}

	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		logger.LogAtLevel("info", "error", "ERROR: Failed to read config file %s: %v", configPath, err)
		return fmt.Errorf("failed to read config file: %v", err)
	}

	config := &Config{}
	if err := json.Unmarshal(data, config); err != nil {
		logger.LogAtLevel("info", "error", "ERROR: Failed to parse config file %s: %v", configPath, err)
		return fmt.Errorf("failed to parse config file: %v", err)
	}

	// Validate required fields and set defaults
	validateAndSetDefaults(config)
	
	AppConfig = config
	// Use level-aware logging - this will respect the configured log level
	logger.LogAtLevel(config.Server.LogLevel, "info", "INFO: Configuration loaded successfully from %s", configPath)
	return nil
}

// getDefaultConfig returns the default configuration
func getDefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Port:      ":58080",
			StaticDir: "static",
			LogLevel:  "info",
			UseEmbedded: true,
		},
		Database: DatabaseConfig{
			Path:   "./gatekeeper.db",
			Driver: "sqlite3",
		},
		Session: SessionConfig{
			SecretKey: "something-very-secret",
			Name:      "session-name",
			MaxAge:    86400, // 24 hours in seconds
		},
		Templates: TemplatesConfig{
			Directory: "templates",
			Pattern:   "*.html",
			UseEmbedded: true,
		},
		Admin: AdminConfig{
			Username: "admin",
			Password: "admin",
			Role:     "approver",
		},
		Security: SecurityConfig{
			UsernamePattern: `^[\p{Han}]+[a-zA-Z]*\w*\d+$`,
			AllowedRoles:    []string{"applicant", "approver"},
			BcryptCost:      12,
		},
		Expiration: ExpirationConfig{
			CleanupInterval: 5,
			Enabled:         true,
		},
	}
}

// validateAndSetDefaults validates configuration and sets defaults where needed
func validateAndSetDefaults(config *Config) {
	defaults := getDefaultConfig()
	
	// Server defaults
	if config.Server.Port == "" {
		config.Server.Port = defaults.Server.Port
	}
	if config.Server.StaticDir == "" {
		config.Server.StaticDir = defaults.Server.StaticDir
	}
	if config.Server.LogLevel == "" {
		config.Server.LogLevel = defaults.Server.LogLevel
	}
	
	// Database defaults
	if config.Database.Path == "" {
		config.Database.Path = defaults.Database.Path
	}
	if config.Database.Driver == "" {
		config.Database.Driver = defaults.Database.Driver
	}
	
	// Session defaults
	if config.Session.SecretKey == "" {
		config.Session.SecretKey = defaults.Session.SecretKey
	}
	if config.Session.Name == "" {
		config.Session.Name = defaults.Session.Name
	}
	if config.Session.MaxAge == 0 {
		config.Session.MaxAge = defaults.Session.MaxAge
	}
	
	// Templates defaults
	if config.Templates.Directory == "" {
		config.Templates.Directory = defaults.Templates.Directory
	}
	if config.Templates.Pattern == "" {
		config.Templates.Pattern = defaults.Templates.Pattern
	}
	
	// Admin defaults
	if config.Admin.Username == "" {
		config.Admin.Username = defaults.Admin.Username
	}
	if config.Admin.Password == "" {
		config.Admin.Password = defaults.Admin.Password
	}
	if config.Admin.Role == "" {
		config.Admin.Role = defaults.Admin.Role
	}
	
	// Security defaults
	if config.Security.UsernamePattern == "" {
		config.Security.UsernamePattern = defaults.Security.UsernamePattern
	}
	if len(config.Security.AllowedRoles) == 0 {
		config.Security.AllowedRoles = defaults.Security.AllowedRoles
	}
	if config.Security.BcryptCost == 0 {
		config.Security.BcryptCost = defaults.Security.BcryptCost
	}
	
	// Expiration defaults
	if config.Expiration.CleanupInterval == 0 {
		config.Expiration.CleanupInterval = defaults.Expiration.CleanupInterval
	}
}

// SaveConfig saves the current configuration to a file
func SaveConfig(configPath string) error {
	if AppConfig == nil {
		AppConfig = getDefaultConfig()
	}
	
	data, err := json.MarshalIndent(AppConfig, "", "  ")
	if err != nil {
		logger.LogAtLevel("info", "error", "ERROR: Failed to marshal config: %v", err)
		return fmt.Errorf("failed to marshal config: %v", err)
	}
	
	err = ioutil.WriteFile(configPath, data, 0644)
	if err != nil {
		logger.LogAtLevel("info", "error", "ERROR: Failed to write config file %s: %v", configPath, err)
		return fmt.Errorf("failed to write config file: %v", err)
	}
	
	logger.LogAtLevel("info", "info", "INFO: Configuration saved to %s", configPath)
	return nil
}

// GetConfig returns the current configuration
func GetConfig() *Config {
	if AppConfig == nil {
		AppConfig = getDefaultConfig()
	}
	return AppConfig
}