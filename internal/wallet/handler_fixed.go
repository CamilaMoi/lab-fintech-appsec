package wallet

import (
	"database/sql"
	"errors"
	"log"
	"net/http"
)

// FixedBalance is the remediated counterpart of VulnerableBalance.
//
// FIX (A01): the SQL predicate binds BOTH the requested wallet id AND the
// authenticated user's id as owner. A wallet that exists but belongs to someone
// else simply does not match, so the caller can only ever read their own.
//
// The not-found and not-owned cases return the same 404. Distinguishing them
// ("that wallet exists but isn't yours") would leak the existence of other
// users' wallet ids — a resource-enumeration oracle.
func (h *Handler) FixedBalance(w http.ResponseWriter, r *http.Request) {
	caller, ok := user(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "no authenticated user")
		return
	}

	walletID := r.URL.Query().Get("id")
	if walletID == "" {
		writeErr(w, http.StatusBadRequest, "missing wallet id")
		return
	}

	const q = `SELECT id, owner_id, currency, balance_cents
	             FROM wallets
	            WHERE id = ? AND owner_id = ?`
	var resp walletResponse
	err := h.store.DB().QueryRowContext(r.Context(), q, walletID, caller.ID).
		Scan(&resp.ID, &resp.OwnerID, &resp.Currency, &resp.BalanceCents)
	if errors.Is(err, sql.ErrNoRows) {
		// Either the wallet does not exist or it is not owned by the caller;
		// both are indistinguishable to the client on purpose.
		writeErr(w, http.StatusNotFound, "wallet not found")
		return
	}
	if err != nil {
		log.Printf("fixed wallet query: %v", err)
		writeErr(w, http.StatusInternalServerError, "server error")
		return
	}

	writeJSON(w, http.StatusOK, resp)
}
