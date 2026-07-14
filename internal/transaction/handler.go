// Package transaction exposes the money-movement endpoint — the debit path.
// It is the showcase scenario of this lab: a Time-Of-Check-to-Time-Of-Use
// (TOCTOU) race condition, the canonical fintech double-spend.
//
// Unlike SQL injection, this flaw is NOT detectable by gosec or any SAST tool:
// there is no unsafe API call to pattern-match. Every query below is
// parameterized. The bug lives in the *sequencing* of correct operations, which
// is precisely why business-logic vulnerabilities need threat modeling and
// manual review, not just automated scanners.
package transaction

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/CamilaMoi/lab-fintech-appsec/internal/middleware"
	"github.com/CamilaMoi/lab-fintech-appsec/pkg/models"
)

// execer is satisfied by both *sql.DB and *sql.Tx, so recordTransaction works
// whether the caller is running standalone (vulnerable) or inside an atomic
// transaction (fixed).
type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// checkWindow widens the gap between the balance check and the write in the
// vulnerable handler. In production the window is much smaller but still
// exploitable under concurrency; widening it here makes the race deterministic
// for a live demo. This is a teaching artifact, not part of the flaw itself.
const checkWindow = 150 * time.Millisecond

type Handler struct {
	store *models.Store
}

func NewHandler(store *models.Store) *Handler {
	return &Handler{store: store}
}

type debitRequest struct {
	AmountCents int64 `json:"amount_cents"`
}

type debitResponse struct {
	Status          string `json:"status"`
	NewBalanceCents int64  `json:"new_balance_cents"`
	TransactionID   int64  `json:"transaction_id"`
}

// VulnerableDebit demonstrates OWASP A04:2021 — Insecure Design (CWE-362 race
// condition / CWE-367 TOCTOU).
//
// The handler reads the balance, checks it, then writes the new value as an
// absolute figure. Between the read and the write the wallet is unlocked, so
// two concurrent debits both observe the original balance, both pass the check,
// and both overwrite — the second write clobbers the first. The account is
// debited once in the ledger balance while two withdrawals are honored: a
// double-spend.
func (h *Handler) VulnerableDebit(w http.ResponseWriter, r *http.Request) {
	caller, ok := middleware.UserFromContext(r.Context())
	if !ok {
		writeErr(w, http.StatusUnauthorized, "no authenticated user")
		return
	}

	var req debitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.AmountCents <= 0 {
		writeErr(w, http.StatusBadRequest, "amount must be positive")
		return
	}

	db := h.store.DB()

	// CHECK: read current balance.
	var (
		walletID string
		balance  int64
	)
	err := db.QueryRowContext(r.Context(),
		`SELECT id, balance_cents FROM wallets WHERE owner_id = ?`, caller.ID).
		Scan(&walletID, &balance)
	if err != nil {
		log.Printf("vuln debit read: %v", err)
		writeErr(w, http.StatusInternalServerError, "server error")
		return
	}
	if balance < req.AmountCents {
		writeErr(w, http.StatusBadRequest, "insufficient funds")
		return
	}

	// VULNERABILITY (A04 / CWE-367): the wallet is not held between the check
	// above and the write below. Widening this window makes the race obvious.
	time.Sleep(checkWindow)

	// USE: write the new balance as an absolute value, discarding any change a
	// concurrent request may have committed in the meantime (lost update).
	newBalance := balance - req.AmountCents
	if _, err := db.ExecContext(r.Context(),
		`UPDATE wallets SET balance_cents = ? WHERE id = ?`, newBalance, walletID); err != nil {
		log.Printf("vuln debit write: %v", err)
		writeErr(w, http.StatusInternalServerError, "server error")
		return
	}

	txID := recordTransaction(r.Context(), db, walletID, req.AmountCents)
	writeJSON(w, http.StatusOK, debitResponse{
		Status: "ok", NewBalanceCents: newBalance, TransactionID: txID,
	})
}

// recordTransaction appends a ledger row and returns its id (0 on failure —
// this is a lab, so a ledger write failure is only logged).
func recordTransaction(ctx context.Context, q execer, walletID string, amount int64) int64 {
	res, err := q.ExecContext(ctx,
		`INSERT INTO transactions (wallet_id, amount_cents, kind, created_at) VALUES (?, ?, ?, ?)`,
		walletID, amount, "debit", time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		log.Printf("record transaction: %v", err)
		return 0
	}
	id, _ := res.LastInsertId()
	return id
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("transaction: encode response: %v", err)
	}
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
