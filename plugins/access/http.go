package access

import (
	"net/http"
)

// RequirePermission returns a net/http middleware handler that validates whether the resolved subject has permission for a resource and actions.
func (p *Plugin) RequirePermission(resource string, actions ...string) func(next http.Handler) http.Handler {
	return RequirePermissionHTTP(p.ac, ContextRoleResolver, resource, actions...)
}

// RequirePermissionHTTP returns a net/http middleware handler that validates whether the resolved subject has permission for a resource and actions.
func RequirePermissionHTTP(ac *AccessControl, resolver SubjectPermissionResolver, resource string, actions ...string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if resolver == nil {
				resolver = ContextRoleResolver
			}
			roles, err := resolver(r.Context())
			if err != nil {
				http.Error(w, "Forbidden: "+err.Error(), http.StatusForbidden)
				return
			}
			res := ac.AuthorizeRoles(roles, Req(resource, actions...))
			if !res.Success {
				http.Error(w, "Forbidden: "+res.Error, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
