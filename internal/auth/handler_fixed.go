package auth

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"golang.org/x/crypto/bcrypt"

	"github.com/CamilaMoi/lab-fintech-appsec/internal/middleware"
)

// FixedLogin is the remediated counterpart of VulnerableLogin.
//
// Two mitigations, each mapped to a weakness in the vulnerable path:
//
//  1. Injection (A03): the query is parameterized. User input binds as a value
//     and can never change the statement structure.
//  2. Credential storage (A02/A07): the password is checked against a bcrypt
//     hash with a constant-time comparison, not matched as plaintext in SQL.
//
// The response is identical whether the username is unknown or the password is
// wrong, so it cannot be used as a user-enumeration oracle.
func (h *Handler) FixedLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}

	// FIX (A03): parameterized query — the driver sends the value separately
	// from the SQL text, so injection is structurally impossible.
	const q = `SELECT id, username, wallet_id, password_hash FROM users WHERE username = ?`

	var (
		id       int64
		username string
		walletID string
		hash     string
	)
	err := h.store.DB().QueryRowContext(r.Context(), q, req.Username).
		Scan(&id, &username, &walletID, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if err != nil {
		log.Printf("fixed login query: %v", err)
		writeErr(w, http.StatusInternalServerError, "server error")
		return
	}

	// FIX (A02/A07): verify against the bcrypt hash. CompareHashAndPassword is
	// constant-time and never reveals the stored hash.
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)); err != nil {
		writeErr(w, http.StatusUnauthorized, "invalid credentials")
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
