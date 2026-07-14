// Command server is the entry point for the lab-fintech-appsec API.
//
// This is a SECURITY LAB. Some endpoints are intentionally vulnerable and are
// paired with a fixed counterpart so the before/after can be diffed directly.
// It is never meant to run in production. See README.md for the full scope.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/CamilaMoi/lab-fintech-appsec/pkg/config"
	"github.com/CamilaMoi/lab-fintech-appsec/pkg/models"
)

func main() {
	cfg := config.Load()

	store, err := models.New()
	if err != nil {
		log.Fatalf("init store: %v", err)
	}

	mux := http.NewServeMux()

	// Liveness probe. Also reports seed row counts so the data layer can be
	// verified end to end before any business endpoint exists.
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		users, wallets, err := store.Stats(r.Context())
		if err != nil {
			http.Error(w, `{"status":"error"}`, http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"status":  "ok",
			"users":   users,
			"wallets": wallets,
		})
	})

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("lab-fintech-appsec listening on %s", cfg.ListenAddr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server stopped: %v", err)
	}
}

// writeJSON is the single JSON response helper shared by all handlers.
func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("encode response: %v", err)
	}
}
