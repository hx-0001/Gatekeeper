// +build ignore

// This file provides a test runner for the Gatekeeper project
// Run with: go run run_tests.go

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func main() {
	fmt.Println("🧪 Running Gatekeeper Test Suite")
	fmt.Println("================================")
	
	testPackages := []struct {
		name        string
		path        string
		description string
	}{
		{"Models", "./models", "Data model validation tests"},
		{"Database", "./database", "Database operations and schema tests"},
		{"Auth Handlers", "./handlers", "Authentication handler tests (auth_test.go)"},
		{"App Handlers", "./handlers", "Application handler tests (application_test.go)"},
		{"Integration", ".", "End-to-end workflow tests"},
	}
	
	allPassed := true
	
	for _, test := range testPackages {
		fmt.Printf("\n🔍 Running %s Tests...\n", test.name)
		fmt.Printf("   %s\n", test.description)
		
		var cmd *exec.Cmd
		if test.path == "." {
			// For integration tests in root
			cmd = exec.Command("go", "test", "-v", "./integration_test.go")
		} else {
			cmd = exec.Command("go", "test", "-v", test.path)
		}
		
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		
		err := cmd.Run()
		if err != nil {
			fmt.Printf("❌ %s tests failed\n", test.name)
			allPassed = false
		} else {
			fmt.Printf("✅ %s tests passed\n", test.name)
		}
	}
	
	fmt.Println("\n" + strings.Repeat("=", 40))
	if allPassed {
		fmt.Println("🎉 All tests passed!")
		fmt.Println("\nNext steps:")
		fmt.Println("1. Run 'go build' to ensure the application compiles")
		fmt.Println("2. Test the application manually with 'sudo ./gatekeeper_app'")
		fmt.Println("3. Consider adding more edge case tests")
	} else {
		fmt.Println("⚠️  Some tests failed. Please review the output above.")
		os.Exit(1)
	}
}