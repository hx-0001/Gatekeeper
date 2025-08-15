# Gatekeeper Project Makefile

.PHONY: help build test test-verbose test-models test-database test-handlers test-integration clean run

# Default target
help:
	@echo "Available targets:"
	@echo "  build         - Build the application"
	@echo "  test          - Run all tests"
	@echo "  test-verbose  - Run all tests with verbose output"
	@echo "  test-models   - Run model tests only"
	@echo "  test-database - Run database tests only"
	@echo "  test-handlers - Run handler tests only"
	@echo "  test-integration - Run integration tests only"
	@echo "  run           - Build and run the application (requires sudo)"
	@echo "  clean         - Clean build artifacts"

# Build the application
build:
	@echo "🔨 Building Gatekeeper..."
	go build -o gatekeeper_app
	@echo "✅ Build complete: gatekeeper_app"

# Run all tests
test:
	@echo "🧪 Running all tests..."
	go test ./models ./database ./handlers .
	@echo "✅ All tests completed"

# Run tests with verbose output
test-verbose:
	@echo "🧪 Running all tests (verbose)..."
	go test -v ./models ./database ./handlers .

# Run model tests only
test-models:
	@echo "🧪 Running model tests..."
	go test -v ./models

# Run database tests only
test-database:
	@echo "🧪 Running database tests..."
	go test -v ./database

# Run handler tests only
test-handlers:
	@echo "🧪 Running handler tests..."
	go test -v ./handlers

# Run integration tests only
test-integration:
	@echo "🧪 Running integration tests..."
	go test -v -run TestComplete
	go test -v -run TestEndToEnd
	go test -v -run TestAuthentication

# Build and run (requires sudo for iptables)
run: build
	@echo "🚀 Starting Gatekeeper (requires sudo for iptables access)..."
	@echo "⚠️  Make sure you have sudo privileges"
	sudo ./gatekeeper_app

# Clean build artifacts
clean:
	@echo "🧹 Cleaning build artifacts..."
	rm -f gatekeeper_app gatekeeper_build
	@echo "✅ Clean complete"

# Development workflow
dev: clean build test
	@echo "🎉 Development build and test cycle complete"

# Coverage report (requires go cover tools)
coverage:
	@echo "📊 Generating test coverage report..."
	go test -coverprofile=coverage.out ./models ./database ./handlers
	go tool cover -html=coverage.out -o coverage.html
	@echo "✅ Coverage report generated: coverage.html"

# Benchmark tests
benchmark:
	@echo "⚡ Running benchmark tests..."
	go test -bench=. ./models ./database ./handlers