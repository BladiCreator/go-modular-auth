package admin

import (
	"context"
	"net/http"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

// Context keys for request context store.
type contextKey string

const (
	CallerContextKey contextKey = "admin_caller"
)

// RequirePermission returns a standard net/http middleware handler verifying administrative permissions for incoming requests.
func (p *Plugin) RequirePermission(permissions Permissions, connector ...Connector) func(next http.Handler) http.Handler {
	conn := ConnectorAND
	if len(connector) > 0 {
		conn = connector[0]
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			caller := p.extractCallerFromRequest(r)
			if !p.hasPermission(caller, permissions, conn) {
				http.Error(w, "Forbidden: Administrative permissions required", http.StatusForbidden)
				return
			}
			ctx := context.WithValue(r.Context(), CallerContextKey, caller)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireAdmin returns a standard net/http middleware handler requiring the caller to possess an administrator role or ID.
func (p *Plugin) RequireAdmin() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			caller := p.extractCallerFromRequest(r)
			mockUser := &entity.User{ID: caller.UserID, Role: caller.Role}
			if !p.isUserAdmin(mockUser) {
				http.Error(w, "Forbidden: Admin role required", http.StatusForbidden)
				return
			}
			ctx := context.WithValue(r.Context(), CallerContextKey, caller)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func (p *Plugin) extractCallerFromRequest(r *http.Request) CallerContext {
	if caller, ok := r.Context().Value(CallerContextKey).(CallerContext); ok {
		return caller
	}
	if u, ok := r.Context().Value(CallerContextKey).(*entity.User); ok && u != nil {
		return CallerContext{UserID: u.ID, Role: u.Role}
	}
	if u, ok := r.Context().Value("user").(*entity.User); ok && u != nil {
		return CallerContext{UserID: u.ID, Role: u.Role}
	}
	userID := r.Header.Get("X-User-ID")
	role := r.Header.Get("X-User-Role")
	return CallerContext{
		UserID: userID,
		Role:   role,
	}
}
