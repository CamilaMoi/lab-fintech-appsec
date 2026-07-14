// Package config centralizes runtime configuration for the lab server.
//
// Everything is sourced from environment variables with lab-safe defaults so
// the project runs with zero setup. The defaults are deliberately insecure and
// are called out as such — in a real service these values MUST come from a
// secret manager (see docs/adr-001-auth-strategy.md).
package config

import "os"

type Config struct {
	// JWTSecret signs and verifies session tokens (HS256).
	JWTSecret []byte
	// ListenAddr is the host:port the HTTP server binds to.
	ListenAddr string
}

// Load reads configuration from the environment, applying lab defaults.
func Load() Config {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		// LAB DEFAULT ONLY. A committed, guessable secret would let anyone
		// forge tokens. Production must inject a high-entropy secret out of band.
		secret = "lab-insecure-development-secret-change-me"
	}

	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	return Config{
		JWTSecret:  []byte(secret),
		ListenAddr: addr,
	}
}
