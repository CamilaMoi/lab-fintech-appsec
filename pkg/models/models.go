// Package models holds the domain types and the in-memory data store used by
// the lab. Persistence is intentionally out of scope: the store is a SQLite
// database opened in :memory: mode, so it is rebuilt and reseeded on every
// process start. A real SQL engine (rather than Go maps) is required because
// the injection scenario in internal/auth is only meaningful against an actual
// query planner.
package models

import (
	"context"
	"database/sql"
	"fmt"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite" // pure-Go driver, registers the "sqlite" name (no CGO)
)

// User is an account holder. Password is stored twice on purpose:
//
//   - Password: plaintext, consumed ONLY by the intentionally vulnerable auth
//     handler. It is a teaching artifact and would never exist in real code.
//   - PasswordHash: bcrypt, consumed by the fixed auth handler.
type User struct {
	ID       int64
	Username string
	WalletID string
}

// Wallet belongs to exactly one User via OwnerID. The IDOR scenario in
// internal/wallet hinges on whether OwnerID is checked against the caller.
type Wallet struct {
	ID           string
	OwnerID      int64
	Currency     string
	BalanceCents int64
}

// Transaction is a movement of funds against a Wallet.
type Transaction struct {
	ID          int64
	WalletID    string
	AmountCents int64
	Kind        string
	CreatedAt   string
}

// Store wraps the SQLite handle. Handlers reach the raw *sql.DB through DB();
// the vulnerable handlers build queries by string concatenation against it,
// while the fixed handlers use parameterized statements.
type Store struct {
	db *sql.DB
}

// DB exposes the underlying handle so handlers can run their own queries.
func (s *Store) DB() *sql.DB { return s.db }

// New opens an in-memory SQLite database, creates the schema, and seeds it.
func New() (*Store, error) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	// CRITICAL: with modernc.org/sqlite, ":memory:" is scoped to a single
	// connection. The pool would otherwise hand out fresh, empty databases and
	// the seed would vanish. Pinning to one connection keeps one shared DB.
	db.SetMaxOpenConns(1)

	s := &Store{db: db}
	if err := s.migrate(context.Background()); err != nil {
		return nil, err
	}
	if err := s.seed(context.Background()); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate(ctx context.Context) error {
	const schema = `
CREATE TABLE users (
    id            INTEGER PRIMARY KEY,
    username      TEXT UNIQUE NOT NULL,
    password      TEXT NOT NULL,  -- plaintext: consumed ONLY by the vulnerable handler (lab artifact)
    password_hash TEXT NOT NULL,  -- bcrypt: consumed by the fixed handler
    wallet_id     TEXT NOT NULL
);

CREATE TABLE wallets (
    id            TEXT PRIMARY KEY,
    owner_id      INTEGER NOT NULL,
    currency      TEXT NOT NULL,
    balance_cents INTEGER NOT NULL
);

CREATE TABLE transactions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    wallet_id    TEXT NOT NULL,
    amount_cents INTEGER NOT NULL,
    kind         TEXT NOT NULL,
    created_at   TEXT NOT NULL
);`
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}

func (s *Store) seed(ctx context.Context) error {
	seedUsers := []struct {
		id       int64
		username string
		password string
		walletID string
	}{
		{1, "alice", "alice123", "wallet-001"},
		{2, "bob", "bob123", "wallet-002"},
	}

	for _, u := range seedUsers {
		hash, err := bcrypt.GenerateFromPassword([]byte(u.password), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("seed hash for %s: %w", u.username, err)
		}
		_, err = s.db.ExecContext(ctx,
			`INSERT INTO users (id, username, password, password_hash, wallet_id) VALUES (?, ?, ?, ?, ?)`,
			u.id, u.username, u.password, string(hash), u.walletID)
		if err != nil {
			return fmt.Errorf("seed user %s: %w", u.username, err)
		}
	}

	seedWallets := []Wallet{
		{ID: "wallet-001", OwnerID: 1, Currency: "BRL", BalanceCents: 1_500_000},
		{ID: "wallet-002", OwnerID: 2, Currency: "BRL", BalanceCents: 999_900},
	}
	for _, w := range seedWallets {
		_, err := s.db.ExecContext(ctx,
			`INSERT INTO wallets (id, owner_id, currency, balance_cents) VALUES (?, ?, ?, ?)`,
			w.ID, w.OwnerID, w.Currency, w.BalanceCents)
		if err != nil {
			return fmt.Errorf("seed wallet %s: %w", w.ID, err)
		}
	}
	return nil
}

// Stats returns row counts, used by the /health probe to prove the schema and
// seed loaded correctly.
func (s *Store) Stats(ctx context.Context) (users, wallets int, err error) {
	if err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&users); err != nil {
		return 0, 0, fmt.Errorf("count users: %w", err)
	}
	if err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM wallets`).Scan(&wallets); err != nil {
		return 0, 0, fmt.Errorf("count wallets: %w", err)
	}
	return users, wallets, nil
}
