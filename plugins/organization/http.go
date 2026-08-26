package organization

import (
	"context"
	"net/http"
)

// Context keys for request context store.
type contextKey string

const (
	MemberContextKey       contextKey = "org_member"
	OrganizationContextKey contextKey = "org_entity"
)

// RequireMember returns a net/http middleware handler verifying that the user belongs to the target organization.
func (p *Plugin) RequireMember(headerName ...string) func(next http.Handler) http.Handler {
	hdr := "X-Organization-ID"
	if len(headerName) > 0 && headerName[0] != "" {
		hdr = headerName[0]
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			orgID := p.extractOrgID(r, hdr)
			userID := r.Header.Get("X-User-ID")
			if u, ok := r.Context().Value("user_id").(string); ok && u != "" {
				userID = u
			}
			if orgID == "" || userID == "" {
				http.Error(w, "Unauthorized: Organization ID and User ID required", http.StatusUnauthorized)
				return
			}

			member, err := p.repo.GetMember(r.Context(), orgID, userID)
			if err != nil || member == nil {
				http.Error(w, "Forbidden: Not an active member of organization", http.StatusForbidden)
				return
			}

			ctx := context.WithValue(r.Context(), MemberContextKey, member)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequirePermission returns a net/http middleware handler verifying organization membership and required permissions.
func (p *Plugin) RequirePermission(requiredPermissions Permissions, headerName ...string) func(next http.Handler) http.Handler {
	hdr := "X-Organization-ID"
	if len(headerName) > 0 && headerName[0] != "" {
		hdr = headerName[0]
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			orgID := p.extractOrgID(r, hdr)
			userID := r.Header.Get("X-User-ID")
			if u, ok := r.Context().Value("user_id").(string); ok && u != "" {
				userID = u
			}
			if orgID == "" || userID == "" {
				http.Error(w, "Unauthorized: Organization ID and User ID required", http.StatusUnauthorized)
				return
			}

			member, err := p.repo.GetMember(r.Context(), orgID, userID)
			if err != nil || member == nil {
				http.Error(w, "Forbidden: Not an active member of organization", http.StatusForbidden)
				return
			}

			allowed, err := p.CheckPermission(r.Context(), orgID, member.Role, requiredPermissions)
			if err != nil || !allowed {
				http.Error(w, "Forbidden: Insufficient organization permissions", http.StatusForbidden)
				return
			}

			ctx := context.WithValue(r.Context(), MemberContextKey, member)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func (p *Plugin) extractOrgID(r *http.Request, header string) string {
	if id := r.Header.Get(header); id != "" {
		return id
	}
	if id := r.URL.Query().Get("org_id"); id != "" {
		return id
	}
	return ""
}
