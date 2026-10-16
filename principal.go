package auth

import "context"

// PrincipalType classifies the authenticated identity.
type PrincipalType string

// Core principal types. Plugins may define additional types.
const (
	PrincipalUser           PrincipalType = "user"
	PrincipalServiceAccount PrincipalType = "service_account"
	PrincipalAPIKey         PrincipalType = "api_key"
)

// Principal is the authenticated identity interacting with the system. It
// is the boundary between Authentication (who) and Authorization (what):
// authorization plugins consume a Principal, never a Session directly.
type Principal struct {
	Subject string
	Type    PrincipalType
}

type principalKey struct{}

// WithPrincipal returns a context carrying p. Transport adapters call it
// after resolving the request credentials.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFrom returns the Principal stored in ctx, if any.
func PrincipalFrom(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}
