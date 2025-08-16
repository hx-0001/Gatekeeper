package main

import (
	"flag"
	"gatekeeper/config"
	"gatekeeper/database"
	"gatekeeper/handlers"
	"log"
	"net/http"
)

func main() {
	// Parse command line flags
	configPath := flag.String("config", "config.json", "Path to configuration file")
	flag.Parse()

	// Load configuration
	if err := config.LoadConfig(*configPath); err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	cfg := config.GetConfig()
	
	// Initialize database
	database.InitDB(cfg.Database.Path)

	// Initialize handlers with configuration
	handlers.InitHandlers(cfg)

	// Start expiration cleanup service
	handlers.StartExpirationCleanupService()

	// Load default firewall rules at startup
	if err := handlers.LoadDefaultRulesAtStartup(); err != nil {
		log.Printf("Warning: Failed to load default rules: %v", err)
	}

	// Setup routes
	http.HandleFunc("/login", handlers.LoginHandler)
	http.HandleFunc("/register", handlers.RegisterHandler)
	http.HandleFunc("/logout", handlers.LogoutHandler)

	// Authenticated routes
	http.HandleFunc("/", handlers.AuthMiddleware(handlers.DashboardHandler))
	http.HandleFunc("/apply", handlers.AuthMiddleware(handlers.ApplyHandler))
	http.HandleFunc("/change-password", handlers.AuthMiddleware(handlers.ChangePasswordHandler))

	// Approver-only routes
	http.HandleFunc("/admin/users", handlers.AuthMiddleware(handlers.ApproverMiddleware(handlers.AdminUsersHandler)))
	http.HandleFunc("/admin/approve", handlers.AuthMiddleware(handlers.ApproverMiddleware(handlers.ApproveHandler)))
	http.HandleFunc("/admin/reject", handlers.AuthMiddleware(handlers.ApproverMiddleware(handlers.RejectHandler)))
	http.HandleFunc("/admin/remove", handlers.AuthMiddleware(handlers.ApproverMiddleware(handlers.RemoveHandler)))
	http.HandleFunc("/admin/retry", handlers.AuthMiddleware(handlers.ApproverMiddleware(handlers.RetryHandler)))
	http.HandleFunc("/admin/reset-password", handlers.AuthMiddleware(handlers.ApproverMiddleware(handlers.ResetPasswordHandler)))
	
	// Default rules management routes
	http.HandleFunc("/admin/default-rules", handlers.AuthMiddleware(handlers.ApproverMiddleware(handlers.DefaultRulesHandler)))
	http.HandleFunc("/admin/default-rules/add", handlers.AuthMiddleware(handlers.ApproverMiddleware(handlers.AddDefaultRuleHandler)))
	http.HandleFunc("/admin/default-rules/update", handlers.AuthMiddleware(handlers.ApproverMiddleware(handlers.UpdateDefaultRuleHandler)))
	http.HandleFunc("/admin/default-rules/delete", handlers.AuthMiddleware(handlers.ApproverMiddleware(handlers.DeleteDefaultRuleHandler)))
	http.HandleFunc("/api/default-rules", handlers.AuthMiddleware(handlers.ApproverMiddleware(handlers.DefaultRulesAPIHandler)))

	// Serve static files
	fs := http.FileServer(http.Dir(cfg.Server.StaticDir))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	log.Printf("Starting server on %s", cfg.Server.Port)
	log.Printf("Database: %s", cfg.Database.Path)
	log.Printf("Static files: %s", cfg.Server.StaticDir)
	log.Printf("Templates: %s/%s", cfg.Templates.Directory, cfg.Templates.Pattern)
	
	if err := http.ListenAndServe(cfg.Server.Port, nil); err != nil {
		log.Fatalf("could not start server: %s\n", err)
	}
}
