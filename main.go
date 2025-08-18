package main

import (
	"embed"
	"flag"
	"gatekeeper/config"
	"gatekeeper/database"
	"gatekeeper/handlers"
	"io/fs"
	"log"
	"net/http"
)

//go:embed static
var staticFiles embed.FS

//go:embed templates
var templateFiles embed.FS

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

	// Initialize handlers with configuration and embedded files
	handlers.InitHandlers(cfg, templateFiles)

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

	// Serve static files (embedded or filesystem)
	if cfg.Server.UseEmbedded {
		staticFS, err := fs.Sub(staticFiles, "static")
		if err != nil {
			log.Fatalf("Failed to create static file system: %v", err)
		}
		http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))
	} else {
		fileServer := http.FileServer(http.Dir(cfg.Server.StaticDir))
		http.Handle("/static/", http.StripPrefix("/static/", fileServer))
	}

	log.Printf("Starting server on %s", cfg.Server.Port)
	log.Printf("Database: %s", cfg.Database.Path)
	if cfg.Server.UseEmbedded {
		log.Printf("Static files: embedded")
	} else {
		log.Printf("Static files: %s", cfg.Server.StaticDir)
	}
	if cfg.Templates.UseEmbedded {
		log.Printf("Templates: embedded")
	} else {
		log.Printf("Templates: %s/%s", cfg.Templates.Directory, cfg.Templates.Pattern)
	}
	
	if err := http.ListenAndServe(cfg.Server.Port, nil); err != nil {
		log.Fatalf("could not start server: %s\n", err)
	}
}
