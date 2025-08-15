package main

import (
	"gatekeeper/database"
	"gatekeeper/handlers"
	"log"
	"net/http"
)

func main() {
	database.InitDB("./gatekeeper.db")

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
	http.HandleFunc("/admin/reset-password", handlers.AuthMiddleware(handlers.ApproverMiddleware(handlers.ResetPasswordHandler)))

	// Serve static files
	fs := http.FileServer(http.Dir("static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	log.Println("Starting server on :58080")
	if err := http.ListenAndServe(":58080", nil); err != nil {
		log.Fatalf("could not start server: %s\n", err)
	}
}
