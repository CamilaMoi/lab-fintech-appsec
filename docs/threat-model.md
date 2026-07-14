# Threat Model — Fintech Wallet Lab

STRIDE-based threat model for the money-handling flows in this lab: **login**,
**wallet balance read**, and **debit transaction**. The goal is to make the
security reasoning behind each vulnerable/fixed pair explicit — what an attacker
targets, which STRIDE category it falls under, and the control that closes it.

## 1. Scope and assumptions

- **In scope**: the three HTTP flows above and their data store.
- **Trust boundary**: the network edge in front of the HTTP API. Everything the
  client sends (JSON bodies, query params, the `Authorization` header) is
  **untrusted**. The server and the in-memory database sit inside the boundary.
- **Assumptions**: single process; SQLite `:memory:` reseeded on start;
  transport is plain HTTP in the lab but assumed to be TLS-terminated in any
  real deployment; one JWT signing secret shared by the process.
- **Out of scope (lab)**: DoS/rate-limiting, TLS, key rotation, persistence,
  multi-tenant isolation, refresh tokens. Called out as residual risk in §5.

## 2. Assets

| Asset | Why it matters |
|---|---|
| User credentials | Compromise = full account takeover |
| Session token (JWT) | Bearer of identity; forgery = impersonation |
| Wallet balance | Confidential financial data |
| Wallet integrity (funds) | Must never be spendable beyond the real balance |
| Transaction ledger | Record of movement; basis for reconciliation |

## 3. Data-flow overview

```
client ──(1) POST /login  {username,password}──▶ auth handler ──▶ users table
client ◀─(2) JWT──────────────────────────────── auth handler
client ──(3) GET /wallet?id  + Bearer JWT───────▶ wallet handler ──▶ wallets table
client ──(4) POST /transaction {amount} + JWT───▶ tx handler ──▶ wallets + transactions
```

Trust boundary is crossed on every inbound arrow. The three implemented
scenarios are the three most security-relevant crossings.

## 4. STRIDE analysis

### 4.1 Login (flow 1–2) — implemented pair: `internal/auth`

| STRIDE | Threat | Control (fixed handler) |
|---|---|---|
| **Spoofing** | Authenticate as another user without credentials | Parameterized query + bcrypt verification; identity only asserted after both succeed |
| **Tampering** | Alter the query structure to change auth logic | **This is the vulnerable scenario (A03).** Fix: values bind as data, never as SQL |
| **Repudiation** | Deny having logged in | Out of scope (no audit log in lab); noted in §5 |
| **Information disclosure** | Distinguish "user unknown" vs "wrong password" (enumeration) | Identical error + status for both cases |
| **Elevation of privilege** | SQLi `' OR '1'='1' --` returns the first row and bypasses auth | Parameterized query makes the payload a literal username that matches nothing |

**Vulnerability shown**: SQL injection via string formatting
(`handler.go`, gosec **G201 / CWE-89**). The query is assembled with
`fmt.Sprintf` interpolating `username`/`password`, so input rewrites the
`WHERE` clause.
**Fix** (`handler_fixed.go`): parameterized `WHERE username = ?` and
`bcrypt.CompareHashAndPassword`. Two weaknesses closed — injection (A03) and
plaintext credential comparison (A02/A07).

### 4.2 Wallet read (flow 3) — implemented pair: `internal/wallet`

| STRIDE | Threat | Control (fixed handler) |
|---|---|---|
| **Spoofing** | Call without a valid token | JWT guard (`middleware.Auth`) rejects missing/invalid tokens |
| **Tampering** | Forge a token (e.g. `alg:none`) | HS256 pinned in two places; asymmetric/none rejected |
| **Information disclosure** | Read another user's balance by guessing their wallet id | **This is the vulnerable scenario (A01/IDOR).** Fix: query scoped to `owner_id = caller` |
| **Elevation of privilege** | Authenticated user acts on data they don't own | Authorization enforced at the data layer, not just authentication |

**Vulnerability shown**: IDOR (`handler.go`, **A01 Broken Access Control**). The
handler is authenticated but fetches the wallet **by id alone** — Alice reads
Bob's balance with `?id=wallet-002`.
**Fix** (`handler_fixed.go`): `WHERE id = ? AND owner_id = ?` binds the
authenticated user; a not-owned wallet is indistinguishable from a missing one
(no enumeration oracle).

### 4.3 Debit transaction (flow 4) — implemented pair: `internal/transaction`

| STRIDE | Threat | Control (fixed handler) |
|---|---|---|
| **Tampering** | Spend the same balance twice via concurrent requests | **This is the vulnerable scenario (A04/TOCTOU).** Fix: atomic guarded decrement |
| **Tampering** | Negative/zero amount to inflate balance | Amount validated `> 0` in both handlers to isolate the race as the only variable |
| **Repudiation** | Deny a debit | Ledger row written; in the fix, in the same DB transaction as the debit |
| **Elevation of privilege** | Withdraw beyond available funds | Guard `balance_cents >= ?` evaluated atomically with the write |

**Vulnerability shown**: TOCTOU race / double-spend (`handler.go`,
**A04 Insecure Design / CWE-362 / CWE-367**). The handler reads the balance,
checks it, then writes an absolute new value; between check and write the wallet
is unlocked, so two concurrent debits both pass and the second write clobbers
the first (lost update). Two R$10.000 debits succeed against a R$15.000 balance.
**Fix** (`handler_fixed.go`): a single atomic statement —
`UPDATE wallets SET balance_cents = balance_cents - ? WHERE owner_id = ? AND balance_cents >= ?` —
inside a DB transaction, with `RowsAffected` as the authoritative check. The
relative decrement (not an absolute write) is what prevents the lost update.

> **Why this scenario matters most:** unlike the injection, gosec (and SAST in
> general) does **not** flag this — every query is parameterized and there is no
> unsafe API to pattern-match. The flaw is in the *sequencing* of correct
> operations. It is the concrete argument for why automated scanning does not
> replace threat modeling and manual review, especially for business-logic and
> money-movement code.

## 5. Residual risks (accepted for the lab, would be addressed in production)

- **Secret management** — the JWT secret has a hardcoded lab default (gosec
  **G101**, intentionally left visible and triaged, not suppressed). Production:
  inject from a secret manager; rotate. See `adr-001-auth-strategy.md`.
- **Token lifecycle** — 1h expiry, no revocation/refresh. Production: refresh
  tokens + a revocation path.
- **Auditing / non-repudiation** — no structured audit log of auth and money
  events.
- **DoS / rate limiting** — no throttling on login or transaction endpoints.
- **Transport security** — assumes TLS termination upstream; not configured in
  the lab.
- **Race hardening at scale** — the atomic UPDATE is correct on a single SQLite
  writer; a distributed deployment would also need the same guarantee at the
  database isolation level (e.g. `SELECT ... FOR UPDATE` / serializable txns).
