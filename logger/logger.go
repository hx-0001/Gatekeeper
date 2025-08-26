package logger

import (
	"fmt"
	"log"
	"strings"
)

// LogLevel represents different logging levels
type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR
	FATAL
)

var (
	currentLogLevel LogLevel = INFO
	logLevelNames = map[LogLevel]string{
		DEBUG: "DEBUG",
		INFO:  "INFO",
		WARN:  "WARN", 
		ERROR: "ERROR",
		FATAL: "FATAL",
	}
)

// SetLogLevel sets the current logging level
func SetLogLevel(level string) {
	switch strings.ToLower(level) {
	case "debug":
		currentLogLevel = DEBUG
	case "info":
		currentLogLevel = INFO
	case "warn", "warning":
		currentLogLevel = WARN
	case "error":
		currentLogLevel = ERROR
	case "fatal":
		currentLogLevel = FATAL
	default:
		currentLogLevel = INFO
		log.Printf("WARN: Unknown log level '%s', defaulting to INFO", level)
	}
}

// shouldLog determines if a message should be logged based on current level
func shouldLog(level LogLevel) bool {
	return level >= currentLogLevel
}

// Debug logs a debug message
func Debug(format string, v ...interface{}) {
	if shouldLog(DEBUG) {
		log.Printf("DEBUG: "+format, v...)
	}
}

// Info logs an info message  
func Info(format string, v ...interface{}) {
	if shouldLog(INFO) {
		log.Printf("INFO: "+format, v...)
	}
}

// Warn logs a warning message
func Warn(format string, v ...interface{}) {
	if shouldLog(WARN) {
		log.Printf("WARN: "+format, v...)
	}
}

// Error logs an error message
func Error(format string, v ...interface{}) {
	if shouldLog(ERROR) {
		log.Printf("ERROR: "+format, v...)
	}
}

// Fatal logs a fatal message and exits
func Fatal(format string, v ...interface{}) {
	if shouldLog(FATAL) {
		log.Fatalf("FATAL: "+format, v...)
	}
}

// Printf provides a backward-compatible interface that respects log levels
// It attempts to parse the log level from the message prefix
func Printf(format string, v ...interface{}) {
	message := fmt.Sprintf(format, v...)
	
	// Try to detect log level from message prefix
	upperMsg := strings.ToUpper(message)
	if strings.HasPrefix(upperMsg, "DEBUG:") || strings.Contains(upperMsg, "DEBUG:") {
		if shouldLog(DEBUG) {
			log.Print(message)
		}
	} else if strings.HasPrefix(upperMsg, "INFO:") || strings.Contains(upperMsg, "INFO:") {
		if shouldLog(INFO) {
			log.Print(message)
		}
	} else if strings.HasPrefix(upperMsg, "WARN") || strings.Contains(upperMsg, "WARN") {
		if shouldLog(WARN) {
			log.Print(message)
		}
	} else if strings.HasPrefix(upperMsg, "ERROR:") || strings.Contains(upperMsg, "ERROR:") {
		if shouldLog(ERROR) {
			log.Print(message)
		}
	} else if strings.HasPrefix(upperMsg, "FATAL:") || strings.Contains(upperMsg, "FATAL:") {
		if shouldLog(FATAL) {
			log.Print(message)
		}
	} else {
		// Default to INFO level for messages without explicit level
		if shouldLog(INFO) {
			log.Print(message)
		}
	}
}

// Fatalf provides backward-compatible fatal logging
func Fatalf(format string, v ...interface{}) {
	log.Fatalf(format, v...)
}

// GetLogLevel returns the current log level as a string
func GetLogLevel() string {
	return logLevelNames[currentLogLevel]
}

// LogAtLevel logs a message at the specified level (for early initialization)
func LogAtLevel(configuredLevel, messageLevel, format string, v ...interface{}) {
	// Parse configured level
	var configLevel LogLevel = INFO
	switch strings.ToLower(configuredLevel) {
	case "debug":
		configLevel = DEBUG
	case "info":
		configLevel = INFO
	case "warn", "warning":
		configLevel = WARN
	case "error":
		configLevel = ERROR
	case "fatal":
		configLevel = FATAL
	}
	
	// Parse message level
	var msgLevel LogLevel = INFO
	switch strings.ToLower(messageLevel) {
	case "debug":
		msgLevel = DEBUG
	case "info":
		msgLevel = INFO
	case "warn", "warning":
		msgLevel = WARN
	case "error":
		msgLevel = ERROR
	case "fatal":
		msgLevel = FATAL
	}
	
	// Only log if message level >= configured level
	if msgLevel >= configLevel {
		log.Printf(format, v...)
	}
}