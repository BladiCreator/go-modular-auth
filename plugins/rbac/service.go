package rbac

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	auth "github.com/BladiCreator/go-modular-auth"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
	"github.com/BladiCreator/go-modular-auth-rbac/cache"
	"github.com/BladiCreator/go-modular-auth-rbac/store"
)

type service struct {
	ctx   *sdk.Context
	store store.Store
	cache cache.Cache
	cfg   Config
}

var _ RBAC = (*service)(nil)

func newService(ctx *sdk.Context, cfg Config) *service {
	var c cache.Cache = cfg.Cache
	if c == nil && ctx != nil && ctx.Cache() != nil {
		c = cache.NewCoreCacheAdapter(ctx.Cache(), cfg.CacheTTL)
	}

	return &service{
		ctx:   ctx,
		store: cfg.Store,
		cache: c,
		cfg:   cfg,
	}
}

func (s *service) Authorize(ctx context.Context, principal auth.Principal, permission string, resource Resource) error {
	decision, err := s.Evaluate(ctx, principal, permission, resource)
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return ErrForbidden
	}
	return nil
}

func (s *service) IsAuthorized(ctx context.Context, principal auth.Principal, permission string, resource Resource) (bool, error) {
	decision, err := s.Evaluate(ctx, principal, permission, resource)
	if err != nil {
		return false, err
	}
	return decision.Allowed, nil
}

func (s *service) Evaluate(ctx context.Context, principal auth.Principal, permission string, resource Resource) (*Decision, error) {
	if principal.Subject == "" {
		return nil, ErrPrincipalRequired
	}
	if permission == "" {
		return nil, ErrPermissionRequired
	}

	cacheKey := cache.BuildKey(principal, permission, resource.Type, resource.ID, resource.OrganizationID, resource.ServiceID)

	if s.cache != nil {
		if cached, hit, err := s.cache.GetDecision(ctx, cacheKey); err == nil && hit && cached != nil {
			return &Decision{
				Allowed:          cached.Allowed,
				Reason:           cached.Reason,
				MatchedRole:      cached.MatchedRole,
				Permission:       cached.Permission,
				PrincipalSubject: principal.Subject,
				PrincipalType:    principal.Type,
				EvaluatedAt:      cached.CachedAt,
			}, nil
		}
	}

	assignments, err := s.store.ListAssignmentsByPrincipal(ctx, principal.Subject, principal.Type)
	if err != nil {
		return nil, fmt.Errorf("listing principal assignments: %w", err)
	}

	var matchedRole string
	var allowed bool
	var reason string

	for _, assign := range assignments {
		if !scopeApplies(assign.Scope, assign.ScopeID, resource) {
			continue
		}

		role, err := s.store.GetRole(ctx, assign.RoleID)
		if err != nil {
			continue
		}

		for _, perm := range role.Permissions {
			if matchPermission(perm, permission) {
				allowed = true
				matchedRole = role.Name
				reason = fmt.Sprintf("granted by role %q in scope %q", role.Name, assign.Scope)
				break
			}
		}

		if allowed {
			break
		}
	}

	if !allowed {
		reason = "no matching role permission in active scope"
	}

	decision := &Decision{
		Allowed:          allowed,
		Reason:           reason,
		MatchedRole:      matchedRole,
		Permission:       permission,
		PrincipalSubject: principal.Subject,
		PrincipalType:    principal.Type,
		EvaluatedAt:      s.cfg.Clock(),
	}

	if s.cache != nil {
		_ = s.cache.SetDecision(ctx, cacheKey, &cache.CachedDecision{
			Allowed:     decision.Allowed,
			Reason:      decision.Reason,
			MatchedRole: decision.MatchedRole,
			Permission:  decision.Permission,
			CachedAt:    decision.EvaluatedAt,
		}, s.cfg.CacheTTL)
	}

	if s.ctx != nil && s.ctx.Events() != nil {
		s.ctx.Events().Publish(ctx, auth.Event{
			Name:    EventAccessEvaluated,
			Time:    decision.EvaluatedAt,
			Subject: principal.Subject,
			Payload: AccessEvaluatedPayload{
				PrincipalSubject: principal.Subject,
				PrincipalType:    principal.Type,
				Permission:       permission,
				Allowed:          allowed,
				MatchedRole:      matchedRole,
				ResourceType:     resource.Type,
				ResourceID:       resource.ID,
				OrganizationID:   resource.OrganizationID,
				ServiceID:        resource.ServiceID,
				Timestamp:        decision.EvaluatedAt,
			},
		})
	}

	return decision, nil
}

func (s *service) CreateRole(ctx context.Context, role *Role) error {
	if role == nil || strings.TrimSpace(role.Name) == "" {
		return ErrInvalidInput
	}
	if !role.Scope.Valid() {
		return ErrInvalidScope
	}

	if role.ID == "" {
		role.ID = generateID("role_")
	}

	now := s.cfg.Clock()
	role.CreatedAt = now
	role.UpdatedAt = now

	stRole := &store.Role{
		ID:          role.ID,
		Name:        role.Name,
		Description: role.Description,
		Scope:       store.Scope(role.Scope),
		Permissions: role.Permissions,
		CreatedAt:   role.CreatedAt,
		UpdatedAt:   role.UpdatedAt,
	}

	if err := s.store.CreateRole(ctx, stRole); err != nil {
		return fmt.Errorf("storing role: %w", err)
	}

	if s.ctx != nil && s.ctx.Events() != nil {
		s.ctx.Events().Publish(ctx, auth.Event{
			Name:    EventRoleCreated,
			Time:    now,
			Subject: role.ID,
			Payload: RoleCreatedPayload{
				RoleID:    role.ID,
				Name:      role.Name,
				Scope:     role.Scope,
				Timestamp: now,
			},
		})
	}

	return nil
}

func (s *service) GetRole(ctx context.Context, roleID string) (*Role, error) {
	if roleID == "" {
		return nil, ErrInvalidInput
	}
	stRole, err := s.store.GetRole(ctx, roleID)
	if err != nil {
		return nil, ErrRoleNotFound
	}
	return toDomainRole(stRole), nil
}

func (s *service) GetRoleByName(ctx context.Context, name string) (*Role, error) {
	if name == "" {
		return nil, ErrInvalidInput
	}
	stRole, err := s.store.GetRoleByName(ctx, name)
	if err != nil {
		return nil, ErrRoleNotFound
	}
	return toDomainRole(stRole), nil
}

func (s *service) UpdateRole(ctx context.Context, role *Role) error {
	if role == nil || role.ID == "" || strings.TrimSpace(role.Name) == "" {
		return ErrInvalidInput
	}
	if !role.Scope.Valid() {
		return ErrInvalidScope
	}

	now := s.cfg.Clock()
	role.UpdatedAt = now

	stRole := &store.Role{
		ID:          role.ID,
		Name:        role.Name,
		Description: role.Description,
		Scope:       store.Scope(role.Scope),
		Permissions: role.Permissions,
		CreatedAt:   role.CreatedAt,
		UpdatedAt:   role.UpdatedAt,
	}

	if err := s.store.UpdateRole(ctx, stRole); err != nil {
		return fmt.Errorf("updating role: %w", err)
	}

	_ = s.invalidateCacheForRole(ctx, role.ID)

	if s.ctx != nil && s.ctx.Events() != nil {
		s.ctx.Events().Publish(ctx, auth.Event{
			Name:    EventRoleUpdated,
			Time:    now,
			Subject: role.ID,
			Payload: RoleUpdatedPayload{
				RoleID:    role.ID,
				Name:      role.Name,
				Scope:     role.Scope,
				Timestamp: now,
			},
		})
	}

	return nil
}

func (s *service) DeleteRole(ctx context.Context, roleID string) error {
	if roleID == "" {
		return ErrInvalidInput
	}

	assignments, err := s.store.ListAssignmentsByRole(ctx, roleID)
	if err == nil && len(assignments) > 0 {
		return ErrRoleInUse
	}

	if err := s.store.DeleteRole(ctx, roleID); err != nil {
		return ErrRoleNotFound
	}

	_ = s.invalidateCacheForRole(ctx, roleID)

	if s.ctx != nil && s.ctx.Events() != nil {
		s.ctx.Events().Publish(ctx, auth.Event{
			Name:    EventRoleDeleted,
			Time:    s.cfg.Clock(),
			Subject: roleID,
			Payload: RoleDeletedPayload{
				RoleID:    roleID,
				Timestamp: s.cfg.Clock(),
			},
		})
	}

	return nil
}

func (s *service) ListRoles(ctx context.Context, scope Scope) ([]*Role, error) {
	stRoles, err := s.store.ListRoles(ctx, store.Scope(scope))
	if err != nil {
		return nil, fmt.Errorf("listing roles: %w", err)
	}

	roles := make([]*Role, len(stRoles))
	for i, r := range stRoles {
		roles[i] = toDomainRole(r)
	}
	return roles, nil
}

func (s *service) AssignRole(ctx context.Context, assignment *RoleAssignment) error {
	if assignment == nil || assignment.RoleID == "" || assignment.PrincipalSubject == "" {
		return ErrInvalidInput
	}
	if !assignment.Scope.Valid() {
		return ErrInvalidScope
	}

	role, err := s.store.GetRole(ctx, assignment.RoleID)
	if err != nil {
		return ErrRoleNotFound
	}

	if role.Scope != store.Scope(assignment.Scope) {
		return fmt.Errorf("%w: role scope %q does not match assignment scope %q", ErrInvalidScope, role.Scope, assignment.Scope)
	}

	if assignment.ID == "" {
		assignment.ID = generateID("asgn_")
	}
	assignment.CreatedAt = s.cfg.Clock()

	stAssign := &store.RoleAssignment{
		ID:               assignment.ID,
		RoleID:           assignment.RoleID,
		PrincipalSubject: assignment.PrincipalSubject,
		PrincipalType:    assignment.PrincipalType,
		Scope:            store.Scope(assignment.Scope),
		ScopeID:          assignment.ScopeID,
		CreatedAt:        assignment.CreatedAt,
	}

	if err := s.store.CreateAssignment(ctx, stAssign); err != nil {
		return fmt.Errorf("storing role assignment: %w", err)
	}

	if s.cache != nil {
		_ = s.cache.InvalidatePrincipal(ctx, assignment.PrincipalSubject)
	}

	if s.ctx != nil && s.ctx.Events() != nil {
		s.ctx.Events().Publish(ctx, auth.Event{
			Name:    EventRoleAssigned,
			Time:    assignment.CreatedAt,
			Subject: assignment.PrincipalSubject,
			Payload: RoleAssignedPayload{
				AssignmentID:     assignment.ID,
				RoleID:           assignment.RoleID,
				PrincipalSubject: assignment.PrincipalSubject,
				PrincipalType:    assignment.PrincipalType,
				Scope:            assignment.Scope,
				ScopeID:          assignment.ScopeID,
				Timestamp:        assignment.CreatedAt,
			},
		})
	}

	return nil
}

func (s *service) RevokeRole(ctx context.Context, assignmentID string) error {
	if assignmentID == "" {
		return ErrInvalidInput
	}

	assignment, err := s.store.GetAssignment(ctx, assignmentID)
	if err != nil {
		return ErrAssignmentNotFound
	}

	if err := s.store.DeleteAssignment(ctx, assignmentID); err != nil {
		return fmt.Errorf("deleting role assignment: %w", err)
	}

	if s.cache != nil {
		_ = s.cache.InvalidatePrincipal(ctx, assignment.PrincipalSubject)
	}

	if s.ctx != nil && s.ctx.Events() != nil {
		s.ctx.Events().Publish(ctx, auth.Event{
			Name:    EventRoleRevoked,
			Time:    s.cfg.Clock(),
			Subject: assignment.PrincipalSubject,
			Payload: RoleRevokedPayload{
				AssignmentID:     assignmentID,
				RoleID:           assignment.RoleID,
				PrincipalSubject: assignment.PrincipalSubject,
				Timestamp:        s.cfg.Clock(),
			},
		})
	}

	return nil
}

func (s *service) ListAssignmentsByPrincipal(ctx context.Context, principal auth.Principal) ([]*RoleAssignment, error) {
	if principal.Subject == "" {
		return nil, ErrPrincipalRequired
	}
	stAssignments, err := s.store.ListAssignmentsByPrincipal(ctx, principal.Subject, principal.Type)
	if err != nil {
		return nil, fmt.Errorf("listing assignments: %w", err)
	}

	assignments := make([]*RoleAssignment, len(stAssignments))
	for i, a := range stAssignments {
		assignments[i] = toDomainAssignment(a)
	}
	return assignments, nil
}

func (s *service) ListAssignmentsByRole(ctx context.Context, roleID string) ([]*RoleAssignment, error) {
	if roleID == "" {
		return nil, ErrInvalidInput
	}
	stAssignments, err := s.store.ListAssignmentsByRole(ctx, roleID)
	if err != nil {
		return nil, fmt.Errorf("listing assignments: %w", err)
	}

	assignments := make([]*RoleAssignment, len(stAssignments))
	for i, a := range stAssignments {
		assignments[i] = toDomainAssignment(a)
	}
	return assignments, nil
}

func (s *service) InvalidatePrincipalCache(ctx context.Context, principalSubject string) error {
	if s.cache != nil && principalSubject != "" {
		return s.cache.InvalidatePrincipal(ctx, principalSubject)
	}
	return nil
}

func (s *service) InvalidateAllCache(ctx context.Context) error {
	if s.cache != nil {
		return s.cache.InvalidateAll(ctx)
	}
	return nil
}

func (s *service) invalidateCacheForRole(ctx context.Context, roleID string) error {
	if s.cache == nil {
		return nil
	}
	assignments, err := s.store.ListAssignmentsByRole(ctx, roleID)
	if err != nil {
		return s.cache.InvalidateAll(ctx)
	}

	for _, a := range assignments {
		_ = s.cache.InvalidatePrincipal(ctx, a.PrincipalSubject)
	}
	return nil
}

func scopeApplies(scope store.Scope, scopeID string, resource Resource) bool {
	switch scope {
	case store.ScopeGlobal:
		return true
	case store.ScopeOrganization:
		return resource.OrganizationID != "" && resource.OrganizationID == scopeID
	case store.ScopeService:
		return resource.ServiceID != "" && resource.ServiceID == scopeID
	default:
		return false
	}
}

func matchPermission(pattern, requested string) bool {
	if pattern == "*" || pattern == requested {
		return true
	}

	if strings.HasSuffix(pattern, ":*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(requested, prefix)
	}

	patternParts := strings.Split(pattern, ":")
	requestedParts := strings.Split(requested, ":")

	if len(patternParts) != len(requestedParts) {
		return false
	}

	for i := range patternParts {
		if patternParts[i] != "*" && patternParts[i] != requestedParts[i] {
			return false
		}
	}

	return true
}

func toDomainRole(r *store.Role) *Role {
	return &Role{
		ID:          r.ID,
		Name:        r.Name,
		Description: r.Description,
		Scope:       Scope(r.Scope),
		Permissions: append([]string(nil), r.Permissions...),
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}
}

func toDomainAssignment(a *store.RoleAssignment) *RoleAssignment {
	return &RoleAssignment{
		ID:               a.ID,
		RoleID:           a.RoleID,
		PrincipalSubject: a.PrincipalSubject,
		PrincipalType:    a.PrincipalType,
		Scope:            Scope(a.Scope),
		ScopeID:          a.ScopeID,
		CreatedAt:        a.CreatedAt,
	}
}

func generateID(prefix string) string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}
