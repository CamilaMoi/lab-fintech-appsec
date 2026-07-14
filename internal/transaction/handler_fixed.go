package transaction

import (
	"encoding/json"
	"net/http"

	"github.com/CamilaMoi/lab-fintech-appsec/internal/middleware"
)

// FixedDebit is the remediated counterpart of VulnerableDebit.
//
// FIX (A04 / CWE-362): the check and the write are collapsed into a single
// atomic statement —
//
//	UPDATE wallets SET balance_cents = balance_cents - ?
//	 WHERE owner_id = ? AND balance_cents >= ?
//
// The database evaluates the guard and applies the debit as one indivisible
// operation, so there is no window for a concurrent request to slip between the
// check and the write. Whether a debit happened is read back from RowsAffected:
// exactly one row means it went through; zero means the funds were no longer
// available (either genuinely insufficient or already spent by a racing
// request). The relative decrement (`balance - ?`) rather than an absolute
// write is what prevents the lost update.
//
// The debit and the ledger insert run in one SQL transaction so they commit or
// roll back together.
func (h *Handler) FixedDebit(w http.ResponseWriter, r *http.Request) {
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

	ctx := r.Context()
	tx, err := h.store.DB().BeginTx(ctx, nil)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "server error")
		return
	}
	defer func() { _ = tx.Rollback() }() // no-op once Commit succeeds

	// Atomic guarded decrement. The WHERE clause is the check; the SET is the
	// write; the engine applies both as one operation.
	res, err := tx.ExecContext(ctx,
		`UPDATE wallets SET balance_cents = balance_cents - ?
		  WHERE owner_id = ? AND balance_cents >= ?`,
		req.AmountCents, caller.ID, req.AmountCents)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "server error")
		return
	}
	affected, err := res.RowsAffected()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "server error")
		return
	}
	if affected == 0 {
		// Guard failed: funds unavailable at commit time. No debit occurred.
		writeErr(w, http.StatusBadRequest, "insufficient funds")
		return
	}

	// Read the post-debit balance and the wallet id within the same tx so the
	// response reflects exactly what was committed.
	var (
		walletID   string
		newBalance int64
	)
	if err := tx.QueryRowContext(ctx,
		`SELECT id, balance_cents FROM wallets WHERE owner_id = ?`, caller.ID).
		Scan(&walletID, &newBalance); err != nil {
		writeErr(w, http.StatusInternalServerError, "server error")
		return
	}

	txID := recordTransaction(ctx, tx, walletID, req.AmountCents)

	if err := tx.Commit(); err != nil {
		writeErr(w, http.StatusInternalServerError, "server error")
		return
	}

	writeJSON(w, http.StatusOK, debitResponse{
		Status: "ok", NewBalanceCents: newBalance, TransactionID: txID,
	})
}
