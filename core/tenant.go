package auth

import "context"

type tenantKey struct{}

// WithOrganization binds an organization identifier to ctx.
func WithOrganization(ctx context.Context, orgID string) context.Context {
	return context.WithValue(ctx, tenantKey{}, orgID)
}

// OrganizationFrom retrieves the organization identifier bound to ctx, if any.
func OrganizationFrom(ctx context.Context) (string, bool) {
	orgID, ok := ctx.Value(tenantKey{}).(string)
	return orgID, ok && orgID != ""
}
