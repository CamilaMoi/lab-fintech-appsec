// Package middleware provides JWT issuance and the authentication guard used to
// protect endpoints. The security-relevant decisions are documented inline
// because this file is the trust boundary for every protected route.
package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const tokenTTL = time.Hour

// ctxKey is unexported so no other package can collide with or overwrite the
// authenticated-user value we store in the request context.
type ctxKey int

const userKey ctxKey = 0

// AuthUser is the principal extracted from a valid token.
type AuthUser struct {
	ID       int64
	Username string
}

// Claims is the JWT payload. The registered Subject claim carries the user ID.
type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// IssueToken mints a signed HS256 token for the given user.
func IssueToken(secret []byte, userID int64, username string) (string, error) {
	now := time.Now()
	claims := Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   strconv.FormatInt(userID, 10),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(tokenTTL)),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
}

// Auth wraps a handler and requires a valid Bearer token.
//
// The signing algorithm is pinned to HS256 in two independent ways: the keyfunc
// asserts the concrete HMAC method, and the parser is constrained with
// WithValidMethods. Trusting the "alg" header from the token would reopen the
// classic "alg: none" bypass and RS256↔HS256 key-confusion attacks.
func Auth(secret []byte, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw := strings.TrimSpace(r.Header.Get("Authorization"))
		const prefix = "Bearer "
		if !strings.HasPrefix(raw, prefix) {
			writeErr(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		tokenStr := strings.TrimSpace(raw[len(prefix):])

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims,
			func(t *jwt.Token) (any, error) {
				if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
				}
				return secret, nil
			},
			jwt.WithValidMethods([]string{"HS256"}),
		)
		if err != nil || !token.Valid {
			writeErr(w, http.StatusUnauthorized, "invalid token")
			return
		}

		id, err := strconv.ParseInt(claims.Subject, 10, 64)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "invalid token subject")
			return
		}

		ctx := context.WithValue(r.Context(), userKey, AuthUser{ID: id, Username: claims.Username})
		next(w, r.WithContext(ctx))
	}
}

// UserFromContext returns the authenticated user injected by Auth.
func UserFromContext(ctx context.Context) (AuthUser, bool) {
	u, ok := ctx.Value(userKey).(AuthUser)
	return u, ok
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"error":%q}`, msg)
}
