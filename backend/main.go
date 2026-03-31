package main

import (
	"log"
	"net/http"
	"os"

	"cspm-dashboard/backend/api"
)

func main() {
	// Scanners are now created per-request from credentials submitted via the
	// API. The server itself needs no AWS credentials to start.
	srv := api.NewServer()

	addr := ":" + envOrDefault("PORT", "8080")
	log.Printf("listening on %s", addr)
	log.Printf("endpoints:")
	log.Printf("  GET  %s/api/health           — liveness check", addr)
	log.Printf("  POST %s/api/scan             — full scan, returns all findings", addr)
	log.Printf("  POST %s/api/findings/summary — finding counts by severity and service", addr)

	if err := http.ListenAndServe(addr, srv.Handler()); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

// envOrDefault returns the value of the environment variable named key, or
// fallback if the variable is unset or empty.
func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
