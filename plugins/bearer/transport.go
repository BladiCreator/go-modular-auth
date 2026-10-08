package bearer

import (
	"context"
	"strings"
)

// TransportAuthenticator is the explicit integration contract for Transport Adapters (HTTP, gRPC, CLI, WebSocket, etc.).
// Any transport layer extracts raw bearer credentials from its protocol carrier and delegates
// authentication to this contract.
type TransportAuthenticator interface {
	// Authenticate validates the transport-neutral input and resolves the Principal.
	Authenticate(ctx context.Context, in AuthenticateInput) (*AuthResult, error)
}

// ExtractBearerToken parses an authorization header value and extracts the raw bearer token.
// It supports case-insensitive "Bearer " prefixing and trims excess whitespace.
//
// Examples:
//   - "Bearer abc123xyz" -> "abc123xyz", nil
//   - "bearer abc123xyz" -> "abc123xyz", nil
//   - "" -> "", ErrMissingBearerToken
//   - "Bearer " -> "", ErrMissingBearerToken
//   - "Basic dXNlcjpwYXNz" -> "", ErrMalformedBearerHeader
func ExtractBearerToken(authHeader string) (string, error) {
	header := strings.TrimSpace(authHeader)
	if header == "" {
		return "", ErrMissingBearerToken
	}

	if strings.EqualFold(header, "bearer") {
		return "", ErrMissingBearerToken
	}

	const prefix = "bearer "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", ErrMalformedBearerHeader
	}

	token := strings.TrimSpace(header[len(prefix):])
	if token == "" {
		return "", ErrMissingBearerToken
	}

	return token, nil
}

type tokenContextKey struct{}

// WithTokenInfo injects the authenticated TokenInfo into the context.
// Transport adapters should invoke this after successful authentication
// so downstream application handlers can inspect token metadata (e.g. scopes).
func WithTokenInfo(ctx context.Context, info *TokenInfo) context.Context {
	if info == nil {
		return ctx
	}
	return context.WithValue(ctx, tokenContextKey{}, info)
}

// TokenInfoFrom extracts the TokenInfo stored in the context, if present.
func TokenInfoFrom(ctx context.Context) (*TokenInfo, bool) {
	info, ok := ctx.Value(tokenContextKey{}).(*TokenInfo)
	return info, ok
}
