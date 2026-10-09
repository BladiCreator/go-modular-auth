// Package http provides standard net/http middleware and request adapters for GoModularAuth.
//
// These adapters operate outside the core engine, allowing any HTTP router (Chi, Gin, Echo,
// standard library http.ServeMux) to authenticate incoming requests and propagate session
// context into the request life cycle.
package http

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth/session"
	"github.com/BladiCreator/go-modular-auth/user"
)

var (
	ErrMissingToken = errors.New("http: missing authentication token")
	ErrUnauthorized = errors.New("http: unauthorized")
)

type contextKey struct{ name string }

var (
	sessionResultKey = contextKey{name: "session_result"}
)

// Extractor retrieves an authentication token string from an HTTP request.
type Extractor func(r *http.Request) string

// BearerExtractor extracts a Bearer token from the standard Authorization header.
func BearerExtractor(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return ""
	}
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
		return strings.TrimSpace(parts[1])
	}
	return ""
}

// CookieExtractor returns an Extractor that reads a token from a named cookie.
func CookieExtractor(cookieName string) Extractor {
	return func(r *http.Request) string {
		cookie, err := r.Cookie(cookieName)
		if err != nil || cookie == nil {
			return ""
		}
		return strings.TrimSpace(cookie.Value)
	}
}

// HeaderExtractor returns an Extractor that reads a token from an arbitrary header.
func HeaderExtractor(headerName string) Extractor {
	return func(r *http.Request) string {
		return strings.TrimSpace(r.Header.Get(headerName))
	}
}

// Options configures the authentication middleware.
type Options struct {
	Extractors   []Extractor
	ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)
}

// Option modifies Options.
type Option func(*Options)

// WithExtractor appends an extractor to the middleware's extraction chain.
func WithExtractor(e Extractor) Option {
	return func(o *Options) {
		if e != nil {
			o.Extractors = append(o.Extractors, e)
		}
	}
}

// WithErrorHandler sets a custom error response handler.
func WithErrorHandler(h func(w http.ResponseWriter, r *http.Request, err error)) Option {
	return func(o *Options) {
		o.ErrorHandler = h
	}
}

func defaultErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": "unauthorized",
	})
}

// Authenticate is a lenient middleware that extracts and validates a session token if present.
// If valid, the session is stored in the request context. If absent or invalid, the request continues unauthenticated.
func Authenticate(a *auth.Auth, opts ...Option) func(http.Handler) http.Handler {
	cfg := Options{
		Extractors: []Extractor{BearerExtractor, CookieExtractor("auth_token")},
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := extractToken(r, cfg.Extractors)
			if token != "" {
				res, err := a.GetSession(r.Context(), token)
				if err == nil && res != nil {
					ctx := context.WithValue(r.Context(), sessionResultKey, res)
					ctx = auth.WithPrincipal(ctx, res.Principal())
					r = r.WithContext(ctx)
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAuth is a strict middleware requiring a valid active session.
// If missing or invalid, it triggers the ErrorHandler (returning 401 Unauthorized by default).
func RequireAuth(a *auth.Auth, opts ...Option) func(http.Handler) http.Handler {
	cfg := Options{
		Extractors:   []Extractor{BearerExtractor, CookieExtractor("auth_token")},
		ErrorHandler: defaultErrorHandler,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := extractToken(r, cfg.Extractors)
			if token == "" {
				cfg.ErrorHandler(w, r, ErrMissingToken)
				return
			}

			res, err := a.RequireSession(r.Context(), token)
			if err != nil || res == nil {
				cfg.ErrorHandler(w, r, ErrUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), sessionResultKey, res)
			ctx = auth.WithPrincipal(ctx, res.Principal())
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func extractToken(r *http.Request, extractors []Extractor) string {
	for _, ext := range extractors {
		if token := ext(r); token != "" {
			return token
		}
	}
	return ""
}

// SessionResultFrom returns the SessionResult stored in ctx, if any.
func SessionResultFrom(ctx context.Context) (*auth.SessionResult, bool) {
	res, ok := ctx.Value(sessionResultKey).(*auth.SessionResult)
	return res, ok && res != nil
}

// SessionFrom returns the authenticated session stored in ctx, if any.
func SessionFrom(ctx context.Context) (*session.Session, bool) {
	if res, ok := SessionResultFrom(ctx); ok {
		return res.Session, true
	}
	return nil, false
}

// UserFrom returns the authenticated user stored in ctx, if any.
func UserFrom(ctx context.Context) (*user.User, bool) {
	if res, ok := SessionResultFrom(ctx); ok {
		return res.User, true
	}
	return nil, false
}

// PrincipalFrom returns the authenticated principal stored in ctx, if any.
func PrincipalFrom(ctx context.Context) (auth.Principal, bool) {
	return auth.PrincipalFrom(ctx)
}
