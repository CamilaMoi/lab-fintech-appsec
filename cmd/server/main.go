// Command server is the entry point for the lab-fintech-appsec API.
//
// This is a SECURITY LAB. Some endpoints are intentionally vulnerable and are
// paired with a fixed counterpart so the before/after can be diffed directly.
// It is never meant to run in production. See README.md for the full scope.
package main

import (
	"log"
	"net/http"
	"time"
)

const listenAddr = ":8080"

func main() {
	mux := http.NewServeMux()

	// Liveness probe. Kept trivial so the skeleton is testable before any
	// business logic exists.
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("lab-fintech-appsec listening on %s", listenAddr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server stopped: %v", err)
	}
}
