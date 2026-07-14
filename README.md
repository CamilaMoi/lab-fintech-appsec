# lab-fintech-appsec

A small Go REST API modeling a fintech investment wallet (authentication,
balance, transactions), built as a **Secure SDLC laboratory**. Each security
scenario ships two implementations of the same feature side by side — an
intentionally **vulnerable** handler and its **fixed** counterpart — so the
before/after can be diffed directly and reviewed as code.

> **This is a security lab, not a product.** Storage is an in-memory SQLite
> database, reseeded on every start — persistence is deliberately out of scope.
> A real SQL engine (rather than Go maps) is used on purpose: the injection
> scenario is only meaningful against an actual query planner.

## OWASP scenarios

| Scenario | OWASP / CWE | Vulnerable | Fixed | What changed |
|---|---|---|---|---|
| **SQL Injection** | A03:2021 / CWE-89 | `internal/auth/handler.go` | `internal/auth/handler_fixed.go` | `fmt.Sprintf` query → parameterized `?` + bcrypt password check |
| **IDOR** | A01:2021 | `internal/wallet/handler.go` | `internal/wallet/handler_fixed.go` | Fetch by id alone → query scoped to `owner_id = caller` |
| **TOCTOU double-spend** | A04:2021 / CWE-362 | `internal/transaction/handler.go` | `internal/transaction/handler_fixed.go` | Non-atomic read-check-write → atomic guarded `UPDATE` in a transaction |

Full reasoning per scenario is in [`docs/threat-model.md`](docs/threat-model.md)
(STRIDE) and [`docs/adr-001-auth-strategy.md`](docs/adr-001-auth-strategy.md).

## Running

```bash
go run ./cmd/server/     # listens on :8080, reseeds the in-memory DB
```

Seed accounts: `alice` / `alice123` (wallet-001, R$15.000) and
`bob` / `bob123` (wallet-002, R$9.999). Balances are stored in cents.

End-to-end walkthrough of all three scenarios against a freshly started server:

```bash
./demo.sh
```

### A taste of the difference

```bash
# SQL injection — bypass on the vulnerable login, blocked on the fixed one
curl -s -X POST localhost:8080/vuln/login --data-binary '{"username":"alice'"'"' --","password":"x"}'   # issues a token
curl -s -X POST localhost:8080/safe/login --data-binary '{"username":"alice'"'"' --","password":"x"}'   # 401
```

Endpoints: `POST /{vuln,safe}/login`, `GET /{vuln,safe}/wallet?id=`,
`POST /{vuln,safe}/transaction`, `GET /me`, `GET /health`. The wallet and
transaction routes require a `Bearer` token.

## Static analysis (SAST)

```bash
go install github.com/securego/gosec/v2/cmd/gosec@latest
gosec ./...
```

CI runs gosec on every push
([`.github/workflows/security.yml`](.github/workflows/security.yml)) and uploads
the results as SARIF to the repository **Security → Code scanning** tab.

### gosec findings (triaged, not hidden)

| Rule | Where | Verdict |
|---|---|---|
| **G201 / CWE-89** SQL string formatting | `internal/auth/handler.go` | **True positive — intentional.** The injection scenario. Fixed variant is clean. |
| **G101** hardcoded credentials | `pkg/config/config.go` | **Accepted risk (lab).** The zero-setup dev JWT secret. Left visible on purpose; production injects it from a secret manager (see ADR-001). |

Findings are left unsuppressed so the triage is auditable — the point of a
security gate is to reason about results, not to silence them.

### What SAST does *not* catch

The TOCTOU double-spend is invisible to gosec: every query is parameterized and
there is no unsafe API to match — the flaw is in the *sequencing* of correct
operations. This is why business-logic and money-movement code needs threat
modeling and manual review, not only automated scanners.

## Not implemented, and why

- **DAST** — needs a running target plus tuning; low return for the time versus
  the documented SAST + threat model.
- **SCA beyond `go mod tidy`** — dependency scanning (Dependabot/Snyk) is setup
  the lab doesn't need to make its point.
- **Frontend / UI** — a security lab's surface is the API, the code diffs, and
  the CI output; a UI would hide the mechanisms being demonstrated.
- **Persistence & tests** — out of scope; the value here is the security
  reasoning and the reproducible vulnerable/fixed pairs.

## Layout

```
cmd/server/         HTTP entry point and route wiring
internal/auth/       login: vulnerable (SQLi) + fixed
internal/wallet/     balance: vulnerable (IDOR) + fixed
internal/transaction/ debit: vulnerable (TOCTOU) + fixed
internal/middleware/  JWT issuance and the auth guard (HS256 pinned)
pkg/config/          env-sourced config with lab defaults
pkg/models/          domain types + in-memory SQLite store and seed
docs/                threat model (STRIDE) + ADR
```
