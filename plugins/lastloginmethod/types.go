package lastloginmethod

import (
	"context"
	"net/http"
)

// ResolveMethodFunc defines the signature for custom authentication method resolvers.
// It receives the current context and HTTP request, returning the resolved method name and a boolean indicating success.
type ResolveMethodFunc func(ctx context.Context, r *http.Request) (string, bool)

// BeforeStoreCookieFunc defines the signature for GDPR consent and pre-cookie storage interceptors.
// If it returns false or an error, cookie storage is skipped without aborting the authentication session.
type BeforeStoreCookieFunc func(ctx context.Context, r *http.Request, method string) (bool, error)

// SetLastLoginMethodParams contains parameters for explicitly setting or updating a user's last login method.
type SetLastLoginMethodParams struct {
	UserID string `json:"userId"`
	Method string `json:"method"`
}
