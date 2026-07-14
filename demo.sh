#!/usr/bin/env bash
#
# demo.sh — end-to-end walkthrough of the three vulnerability scenarios.
#
# Run against a FRESHLY STARTED server so the seed balances are intact:
#
#   Terminal 1:  go run ./cmd/server/
#   Terminal 2:  ./demo.sh
#
# The script logs in as alice, then for each scenario fires the same input at
# the vulnerable and the fixed endpoint so the difference is self-evident.

set -euo pipefail

BASE="${BASE:-http://localhost:8080}"

hr()  { printf '\n%s\n' "------------------------------------------------------------"; }
say() { printf '\n>>> %s\n' "$1"; }

token() {
  curl -s -X POST "$BASE/safe/login" \
    -d '{"username":"alice","password":"alice123"}' \
    | sed 's/.*"token":"//;s/".*//'
}

# --- preflight ---------------------------------------------------------------
if ! curl -sf "$BASE/health" >/dev/null; then
  echo "Server not reachable at $BASE — start it with: go run ./cmd/server/" >&2
  exit 1
fi

TOKEN="$(token)"
[ -n "$TOKEN" ] || { echo "login failed" >&2; exit 1; }
echo "Authenticated as alice (owns wallet-001, balance R\$15.000,00)."

# --- Scenario 1: SQL injection (OWASP A03) -----------------------------------
hr; echo "SCENARIO 1 — SQL Injection (auth)   OWASP A03:2021"

PAYLOAD='{"username":"alice'"'"' --","password":"anything"}'

say "Injection payload against the VULNERABLE login (no valid password):"
echo "  $PAYLOAD"
echo -n "  -> "; curl -s -X POST "$BASE/vuln/login" --data-binary "$PAYLOAD"; echo
echo "  (a token was issued — authentication bypassed)"

say "Same payload against the FIXED login:"
echo -n "  -> "; curl -s -X POST "$BASE/safe/login" --data-binary "$PAYLOAD"; echo
echo "  (rejected — the input was bound as data, not SQL)"

# --- Scenario 2: IDOR (OWASP A01) --------------------------------------------
hr; echo "SCENARIO 2 — Broken Access Control / IDOR (wallet)   OWASP A01:2021"

say "Alice requests BOB's wallet (wallet-002) on the VULNERABLE endpoint:"
echo -n "  -> "; curl -s "$BASE/vuln/wallet?id=wallet-002" -H "Authorization: Bearer $TOKEN"; echo
echo "  (Bob's balance leaked — ownership never checked)"

say "Same request on the FIXED endpoint:"
echo -n "  -> "; curl -s "$BASE/safe/wallet?id=wallet-002" -H "Authorization: Bearer $TOKEN"; echo
echo "  (404 — the row only matches if the caller owns it)"

# --- Scenario 3: TOCTOU race / double-spend (OWASP A04) ----------------------
hr; echo "SCENARIO 3 — Race Condition / TOCTOU double-spend (transaction)   OWASP A04:2021 / CWE-362"

say "Two concurrent R\$10.000 debits against a R\$15.000 balance — VULNERABLE:"
curl -s -X POST "$BASE/vuln/transaction" -H "Authorization: Bearer $TOKEN" -d '{"amount_cents":1000000}' &
curl -s -X POST "$BASE/vuln/transaction" -H "Authorization: Bearer $TOKEN" -d '{"amount_cents":1000000}' &
wait
echo
echo -n "  final balance -> "; curl -s "$BASE/safe/wallet?id=wallet-001" -H "Authorization: Bearer $TOKEN"; echo
echo "  (both debits succeeded — R\$20.000 withdrawn, balance dropped only R\$10.000: double-spend)"

echo
echo "NOTE: restart the server to reseed before demoing the fixed path, then run:"
cat <<'EOF'
  curl -s -X POST http://localhost:8080/safe/transaction -H "Authorization: Bearer $TOKEN" -d '{"amount_cents":1000000}' &
  curl -s -X POST http://localhost:8080/safe/transaction -H "Authorization: Bearer $TOKEN" -d '{"amount_cents":1000000}' &
  wait
  # one succeeds, the other returns "insufficient funds"; final balance R$5.000
EOF

hr; echo "Done."
