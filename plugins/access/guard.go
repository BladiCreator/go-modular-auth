package access

import (
	"context"
	"errors"
	"fmt"
)

var (
	// ErrAccessDenied is returned by guards when authorization fails.
	ErrAccessDenied = errors.New("access denied: insufficient permissions")

	// ErrNoSubjectRoles is returned when no roles could be resolved for the subject.
	ErrNoSubjectRoles = errors.New("access denied: no roles associated with subject")
)

type contextKey string

const subjectRolesKey contextKey = ContextKeySubjectRoles

// SubjectPermissionResolver extracts the assigned roles for a subject from a context.
type SubjectPermissionResolver func(ctx context.Context) ([]string, error)

// ContextRoleResolver is a built-in resolver that retrieves roles stored in the context via WithSubjectRoles.
func ContextRoleResolver(ctx context.Context) ([]string, error) {
	roles, ok := SubjectRolesFromContext(ctx)
	if !ok || len(roles) == 0 {
		return nil, ErrNoSubjectRoles
	}
	return roles, nil
}

// WithSubjectRoles attaches a list of subject role identifiers to a context.
func WithSubjectRoles(ctx context.Context, roles ...string) context.Context {
	return context.WithValue(ctx, subjectRolesKey, roles)
}

// SubjectRolesFromContext extracts attached subject roles from a context.
func SubjectRolesFromContext(ctx context.Context) ([]string, bool) {
	roles, ok := ctx.Value(subjectRolesKey).([]string)
	return roles, ok
}

// RequirePermission returns a guard function that validates whether the subject has the specified actions on a resource.
func RequirePermission(ac *AccessControl, resolver SubjectPermissionResolver, resource string, actions ...string) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		roles, err := resolver(ctx)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrAccessDenied, err)
		}
		result := ac.AuthorizeRoles(roles, Req(resource, actions...))
		if !result.Success {
			return fmt.Errorf("%w: %s", ErrAccessDenied, result.Error)
		}
		return nil
	}
}

// RequireRequest returns a guard function that validates an AuthorizeRequest for the resolved subject.
func RequireRequest(ac *AccessControl, resolver SubjectPermissionResolver, req AuthorizeRequest, connector ...Connector) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		roles, err := resolver(ctx)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrAccessDenied, err)
		}
		result := ac.AuthorizeRoles(roles, req, connector...)
		if !result.Success {
			return fmt.Errorf("%w: %s", ErrAccessDenied, result.Error)
		}
		return nil
	}
}

// AuthorizeSubject evaluates an AuthorizeRequest for a subject resolved from context.
func AuthorizeSubject(ctx context.Context, ac *AccessControl, resolver SubjectPermissionResolver, req AuthorizeRequest, connector ...Connector) AuthorizeResult {
	roles, err := resolver(ctx)
	if err != nil {
		return AuthorizeResult{
			Success: false,
			Error:   fmt.Sprintf("failed to resolve subject roles: %v", err),
		}
	}
	return ac.AuthorizeRoles(roles, req, connector...)
}
