// Package wallet exposes the balance-read endpoints. Like package auth, it
// ships a vulnerable handler and its fixed counterpart side by side. Both are
// mounted behind the JWT guard, so the caller is always authenticated — the
// difference is purely whether authorization (ownership) is enforced.
package wallet

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/CamilaMoi/lab-fintech-appsec/internal/middleware"
	"github.com/CamilaMoi/lab-fintech-appsec/pkg/models"
)

type Handler struct {
	store *models.Store
}

func NewHandler(store *models.Store) *Handler {
	return &Handler{store: store}
}

type walletResponse struct {
	ID           string `json:"id"`
	OwnerID      int64  `json:"owner_id"`
	Currency     string `json:"currency"`
	BalanceCents int64  `json:"balance_cents"`
}

// VulnerableBalance demonstrates OWASP A01:2021 — Broken Access Control (IDOR).
//
// The wallet id comes from the query string (?id=wallet-002). The handler is
// authenticated — a valid token is required — but it never checks that the
// requested wallet belongs to the caller. Alice can therefore read Bob's
// balance simply by asking for his wallet id. Authentication without
// authorization is the whole bug.
func (h *Handler) VulnerableBalance(w http.ResponseWriter, r *http.Request) {
	walletID := r.URL.Query().Get("id")
	if walletID == "" {
		writeErr(w, http.StatusBadRequest, "missing wallet id")
		return
	}

	// VULNERABILITY (A01): the query is parameterized (no injection here), but
	// the row is fetched by id ALONE. Ownership is never verified against the
	// authenticated principal.
	const q = `SELECT id, owner_id, currency, balance_cents FROM wallets WHERE id = ?`
	var resp walletResponse
	err := h.store.DB().QueryRowContext(r.Context(), q, walletID).
		Scan(&resp.ID, &resp.OwnerID, &resp.Currency, &resp.BalanceCents)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "wallet not found")
		return
	}
	if err != nil {
		log.Printf("vuln wallet query: %v", err)
		writeErr(w, http.StatusInternalServerError, "server error")
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// user is a small helper to read the authenticated principal; both handlers
// need it.
func user(r *http.Request) (middleware.AuthUser, bool) {
	return middleware.UserFromContext(r.Context())
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("wallet: encode response: %v", err)
	}
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
