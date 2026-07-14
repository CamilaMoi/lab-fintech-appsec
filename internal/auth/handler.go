// Package auth holds the login endpoints. It ships two implementations of the
// same feature on purpose: handler.go is intentionally vulnerable and
// handler_fixed.go is its remediated counterpart. Diff them to see the fix.
package auth

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/CamilaMoi/lab-fintech-appsec/internal/middleware"
	"github.com/CamilaMoi/lab-fintech-appsec/pkg/models"
)

// Handler carries the dependencies shared by both the vulnerable and fixed
// login endpoints.
type Handler struct {
	store  *models.Store
	secret []byte
}

func NewHandler(store *models.Store, secret []byte) *Handler {
	return &Handler{store: store, secret: secret}
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResponse struct {
	Token    string `json:"token"`
	UserID   int64  `json:"user_id"`
	Username string `json:"username"`
	WalletID string `json:"wallet_id"`
}

// VulnerableLogin demonstrates OWASP A03:2021 — Injection.
//
// User input is concatenated directly into the SQL text, so a payload such as
//
//	{"username": "alice' --",        "password": "anything"}
//	{"username": "x' OR '1'='1' --", "password": "x"}
//
// rewrites the WHERE clause and bypasses authentication. gosec reports this as
// G201 (SQL string formatting).
func (h *Handler) VulnerableLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}

	var (
		id       int64
		username string
		walletID string
	)
	// VULNERABILITY (A03): attacker-controlled input is interpolated straight
	// into the SQL text, so it can alter the query's structure instead of
	// binding as data. gosec reports this as G201 (SQL string formatting).
	db := h.store.DB()
	query := fmt.Sprintf(
		"SELECT id, username, wallet_id FROM users WHERE username = '%s' AND password = '%s'",
		req.Username, req.Password)
	err := db.QueryRowContext(r.Context(), query).Scan(&id, &username, &walletID)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if err != nil {
		log.Printf("vuln login query: %v", err)
		writeErr(w, http.StatusInternalServerError, "server error")
		return
	}

	token, err := middleware.IssueToken(h.secret, id, username)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "server error")
		return
	}
	writeJSON(w, http.StatusOK, loginResponse{
		Token: token, UserID: id, Username: username, WalletID: walletID,
	})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("auth: encode response: %v", err)
	}
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
