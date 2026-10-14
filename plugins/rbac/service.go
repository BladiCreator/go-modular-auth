package rbac

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth/adapter"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
	"github.com/BladiCreator/go-modular-auth/plugins/rbac/cache"
)

type service struct {
	ctx             *sdk.Context
	rolesRepo       *sdk.Repository[Role]
	assignmentsRepo *sdk.Repository[RoleAssignment]
	cache           cache.Cache
	cfg             Config
}

var _ RBAC = (*service)(nil)

func newService(ctx *sdk.Context, cfg Config) *service {
	var c cache.Cache = cfg.Cache
	if c == nil && ctx != nil && ctx.Cache() != nil {
		c = cache.NewCoreCacheAdapter(ctx.Cache(), cfg.CacheTTL)
	}

	var rolesRepo *sdk.Repository[Role]
	var assignmentsRepo *sdk.Repository[RoleAssignment]
	if ctx != nil {
		rolesRepo = sdk.Model[Role](ctx, ModelRBACRoles)
		assignmentsRepo = sdk.Model[RoleAssignment](ctx, ModelRBACAssignments)
	}

	return &service{
		ctx:             ctx,
		rolesRepo:       rolesRepo,
		assignmentsRepo: assignmentsRepo,
		cache:           c,
		cfg:             cfg,
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

	// Resolve contextual multi-tenant organization boundary if not explicitly set
	if resource.OrganizationID == "" {
		if orgID, ok := auth.OrganizationFrom(ctx); ok {
			resource.OrganizationID = orgID
		}
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

	assignments, err := s.ListAssignmentsByPrincipal(ctx, principal)
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

		role, err := s.GetRole(ctx, assign.RoleID)
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
	if s.rolesRepo == nil {
		return errors.New("rbac: repository not initialized")
	}

	// Check unique name constraint
	existing, err := s.rolesRepo.FindOne(ctx, adapter.Eq("name", role.Name))
	if err == nil && existing != nil {
		return ErrRoleAlreadyExists
	}

	if role.ID == "" {
		role.ID = generateID("role_")
	}

	now := s.cfg.Clock()
	role.CreatedAt = now
	role.UpdatedAt = now

	if err := s.rolesRepo.Create(ctx, role); err != nil {
		if errors.Is(err, adapter.ErrConflict) {
			return ErrRoleAlreadyExists
		}
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
	if s.rolesRepo == nil {
		return nil, ErrRoleNotFound
	}
	rec, err := s.rolesRepo.FindOne(ctx, adapter.Eq("id", roleID))
	if err != nil {
		if errors.Is(err, adapter.ErrNotFound) {
			return nil, ErrRoleNotFound
		}
		return nil, err
	}
	return rec, nil
}

func (s *service) GetRoleByName(ctx context.Context, name string) (*Role, error) {
	if name == "" {
		return nil, ErrInvalidInput
	}
	if s.rolesRepo == nil {
		return nil, ErrRoleNotFound
	}
	rec, err := s.rolesRepo.FindOne(ctx, adapter.Eq("name", name))
	if err != nil {
		if errors.Is(err, adapter.ErrNotFound) {
			return nil, ErrRoleNotFound
		}
		return nil, err
	}
	return rec, nil
}

func (s *service) UpdateRole(ctx context.Context, role *Role) error {
	if role == nil || role.ID == "" || strings.TrimSpace(role.Name) == "" {
		return ErrInvalidInput
	}
	if !role.Scope.Valid() {
		return ErrInvalidScope
	}
	if s.rolesRepo == nil {
		return ErrRoleNotFound
	}

	// Check if name is taken by another role
	existing, err := s.rolesRepo.FindOne(ctx, adapter.Eq("name", role.Name))
	if err == nil && existing != nil && existing.ID != role.ID {
		return ErrRoleAlreadyExists
	}

	now := s.cfg.Clock()
	role.UpdatedAt = now

	affected, err := s.rolesRepo.Update(ctx, []adapter.Condition{adapter.Eq("id", role.ID)}, map[string]any{
		"name":        role.Name,
		"description": role.Description,
		"scope":       string(role.Scope),
		"permissions": role.Permissions,
		"updated_at":  role.UpdatedAt,
	})
	if err != nil {
		if errors.Is(err, adapter.ErrConflict) {
			return ErrRoleAlreadyExists
		}
		return fmt.Errorf("updating role: %w", err)
	}
	if affected == 0 {
		return ErrRoleNotFound
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
	if s.rolesRepo == nil || s.assignmentsRepo == nil {
		return ErrRoleNotFound
	}

	cnt, err := s.assignmentsRepo.Count(ctx, adapter.Eq("role_id", roleID))
	if err == nil && cnt > 0 {
		return ErrRoleInUse
	}

	affected, err := s.rolesRepo.Delete(ctx, adapter.Eq("id", roleID))
	if err != nil {
		return err
	}
	if affected == 0 {
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
	if s.rolesRepo == nil {
		return []*Role{}, nil
	}

	var where []adapter.Condition
	if scope != "" {
		where = append(where, adapter.Eq("scope", string(scope)))
	}

	rows, err := s.rolesRepo.FindMany(ctx, adapter.Query{
		Model: ModelRBACRoles,
		Where: where,
	})
	if err != nil {
		return nil, fmt.Errorf("listing roles: %w", err)
	}

	roles := make([]*Role, len(rows))
	for i := range rows {
		roles[i] = &rows[i]
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
	if s.assignmentsRepo == nil {
		return errors.New("rbac: repository not initialized")
	}

	role, err := s.GetRole(ctx, assignment.RoleID)
	if err != nil {
		return ErrRoleNotFound
	}

	if role.Scope != assignment.Scope {
		return fmt.Errorf("%w: role scope %q does not match assignment scope %q", ErrInvalidScope, role.Scope, assignment.Scope)
	}

	// Check if already assigned
	existing, err := s.assignmentsRepo.FindOne(ctx,
		adapter.Eq("role_id", assignment.RoleID),
		adapter.Eq("principal_subject", assignment.PrincipalSubject),
		adapter.Eq("principal_type", string(assignment.PrincipalType)),
		adapter.Eq("scope", string(assignment.Scope)),
		adapter.Eq("scope_id", assignment.ScopeID),
	)
	if err == nil && existing != nil {
		return ErrAssignmentAlreadyExists
	}

	if assignment.ID == "" {
		assignment.ID = generateID("asgn_")
	}
	assignment.CreatedAt = s.cfg.Clock()

	if err := s.assignmentsRepo.Create(ctx, assignment); err != nil {
		if errors.Is(err, adapter.ErrConflict) {
			return ErrAssignmentAlreadyExists
		}
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
	if s.assignmentsRepo == nil {
		return ErrAssignmentNotFound
	}

	assignment, err := s.assignmentsRepo.FindOne(ctx, adapter.Eq("id", assignmentID))
	if err != nil {
		if errors.Is(err, adapter.ErrNotFound) {
			return ErrAssignmentNotFound
		}
		return err
	}

	affected, err := s.assignmentsRepo.Delete(ctx, adapter.Eq("id", assignmentID))
	if err != nil {
		return fmt.Errorf("deleting role assignment: %w", err)
	}
	if affected == 0 {
		return ErrAssignmentNotFound
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
	if s.assignmentsRepo == nil {
		return []*RoleAssignment{}, nil
	}

	where := []adapter.Condition{
		adapter.Eq("principal_subject", principal.Subject),
	}
	if principal.Type != "" {
		where = append(where, adapter.Eq("principal_type", string(principal.Type)))
	}

	rows, err := s.assignmentsRepo.FindMany(ctx, adapter.Query{
		Model: ModelRBACAssignments,
		Where: where,
	})
	if err != nil {
		return nil, fmt.Errorf("listing assignments: %w", err)
	}

	assignments := make([]*RoleAssignment, len(rows))
	for i := range rows {
		assignments[i] = &rows[i]
	}
	return assignments, nil
}

func (s *service) ListAssignmentsByRole(ctx context.Context, roleID string) ([]*RoleAssignment, error) {
	if roleID == "" {
		return nil, ErrInvalidInput
	}
	if s.assignmentsRepo == nil {
		return []*RoleAssignment{}, nil
	}

	rows, err := s.assignmentsRepo.FindMany(ctx, adapter.Query{
		Model: ModelRBACAssignments,
		Where: []adapter.Condition{adapter.Eq("role_id", roleID)},
	})
	if err != nil {
		return nil, fmt.Errorf("listing assignments: %w", err)
	}

	assignments := make([]*RoleAssignment, len(rows))
	for i := range rows {
		assignments[i] = &rows[i]
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
	assignments, err := s.ListAssignmentsByRole(ctx, roleID)
	if err != nil {
		return s.cache.InvalidateAll(ctx)
	}

	for _, a := range assignments {
		_ = s.cache.InvalidatePrincipal(ctx, a.PrincipalSubject)
	}
	return nil
}

func scopeApplies(scope Scope, scopeID string, resource Resource) bool {
	switch scope {
	case ScopeGlobal:
		return true
	case ScopeOrganization:
		return resource.OrganizationID != "" && resource.OrganizationID == scopeID
	case ScopeService:
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

func generateID(prefix string) string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}
