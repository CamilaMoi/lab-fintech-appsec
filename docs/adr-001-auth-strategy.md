# ADR-001 — Authentication strategy: stateless JWT (HS256)

- **Status**: Accepted (lab scope)
- **Date**: 2026-07
- **Context area**: session management for the wallet API

## Context

The API needs to authenticate callers and carry identity across the wallet and
transaction endpoints. Two mainstream options were considered: **server-side
sessions** (opaque session id + server store) and **stateless JWTs** (signed
token the client holds). The choice affects the attack surface, so it is
recorded here rather than left implicit.

## Decision

Use **stateless JWTs signed with HS256**. On successful login the server issues
a token whose `sub` claim carries the user id and which expires in one hour. The
`middleware.Auth` guard validates the token on every protected request and
injects the authenticated principal into the request context.

## Alternatives considered

| Option | Pros | Cons |
|---|---|---|
| **Server-side sessions** | Trivial revocation; no client-side token to steal in bulk; smaller blast radius if signing is misconfigured | Requires a shared session store (state); doesn't fit an in-memory, stateless lab |
| **JWT HS256 (chosen)** | Stateless; no store; simple to demo; standard in Go service meshes | Revocation is hard; a leaked/weak secret forges *any* token; algorithm-confusion foot-guns |
| **JWT RS256** | Asymmetric — verifiers hold only the public key | Key management overhead unjustified for a single-process lab |

## Security considerations (the reason this ADR exists)

1. **Algorithm pinning.** The verifier pins HS256 in two independent ways: the
   keyfunc asserts the concrete HMAC method and the parser is constrained with
   `WithValidMethods([]string{"HS256"})`. Trusting the token's own `alg` header
   reopens the classic **`alg:none` bypass** and **RS256↔HS256 key confusion**.
   This is the single most important control for HS256 JWTs.
2. **Secret strength and storage.** HS256 security collapses to the secret. The
   lab ships a hardcoded default (flagged by gosec **G101**, left visible on
   purpose) so it runs with zero setup. Production **must** inject a
   high-entropy secret from a secret manager and rotate it; the default must
   never ship.
3. **Expiry.** Tokens expire in 1h (`exp` claim, validated by the library).
   Short lifetime is the lab's substitute for the revocation it doesn't have.
4. **No sensitive data in claims.** Claims carry only the user id and username —
   values already known to the holder. JWT payloads are signed, **not
   encrypted**, so they are readable by anyone holding the token.
5. **Transport.** Tokens are bearer credentials; anyone holding one is the user.
   A real deployment must serve only over TLS so tokens can't be sniffed.

## Consequences

- **Positive**: no session store; each request is self-contained; the trust
  boundary for auth is one small, auditable middleware file.
- **Negative / accepted for the lab**: no server-side revocation (a stolen
  token is valid until `exp`); the shared secret is a single point of failure.
  Both are listed as residual risks in `threat-model.md`.
- **If this were production**: add refresh + revocation (short-lived access
  token, longer refresh token with a server-side deny-list), move the secret to
  a managed store, and reconsider RS256 if verification needs to be delegated to
  other services.
