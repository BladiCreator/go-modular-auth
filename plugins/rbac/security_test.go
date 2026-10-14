package rbac_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	rbac "github.com/BladiCreator/go-modular-auth-rbac"
	"github.com/BladiCreator/go-modular-auth-rbac/cache"
)

func TestSecurity_RoleInUseProtection(t *testing.T) {
	ctx := context.Background()
	_, rbacSvc := setupTestRBAC(t)

	role := &rbac.Role{
		ID:          "role-locked",
		Name:        "locked_role",
		Scope:       rbac.ScopeGlobal,
		Permissions: []string{"read"},
	}
	_ = rbacSvc.CreateRole(ctx, role)

	assign := &rbac.RoleAssignment{
		ID:               "asgn-locked",
		RoleID:           role.ID,
		PrincipalSubject: "user-1",
		PrincipalType:    auth.PrincipalUser,
		Scope:            rbac.ScopeGlobal,
	}
	_ = rbacSvc.AssignRole(ctx, assign)

	// Attempt to delete role while assigned must fail with ErrRoleInUse
	err := rbacSvc.DeleteRole(ctx, role.ID)
	if !errors.Is(err, rbac.ErrRoleInUse) {
		t.Fatalf("expected ErrRoleInUse, got: %v", err)
	}

	// Once assignment revoked, deletion should succeed
	_ = rbacSvc.RevokeRole(ctx, assign.ID)
	err = rbacSvc.DeleteRole(ctx, role.ID)
	if err != nil {
		t.Fatalf("expected DeleteRole to succeed after assignment revocation, got: %v", err)
	}
}

func TestSecurity_PrincipalTypeSegregation(t *testing.T) {
	ctx := context.Background()
	_, rbacSvc := setupTestRBAC(t)

	role := &rbac.Role{
		ID:          "role-svc",
		Name:        "svc_role",
		Scope:       rbac.ScopeService,
		Permissions: []string{"internal:sync"},
	}
	_ = rbacSvc.CreateRole(ctx, role)

	// Assigned ONLY to PrincipalServiceAccount
	_ = rbacSvc.AssignRole(ctx, &rbac.RoleAssignment{
		RoleID:           role.ID,
		PrincipalSubject: "ident-same-id",
		PrincipalType:    auth.PrincipalServiceAccount,
		Scope:            rbac.ScopeService,
		ScopeID:          "backend",
	})

	res := rbac.NewServiceResource("sync", "1", "backend")

	// ServiceAccount is allowed
	svcPrincipal := auth.Principal{Subject: "ident-same-id", Type: auth.PrincipalServiceAccount}
	if err := rbacSvc.Authorize(ctx, svcPrincipal, "internal:sync", res); err != nil {
		t.Fatalf("expected service account to be allowed, got: %v", err)
	}

	// User with identical subject ID is denied
	userPrincipal := auth.Principal{Subject: "ident-same-id", Type: auth.PrincipalUser}
	if err := rbacSvc.Authorize(ctx, userPrincipal, "internal:sync", res); !errors.Is(err, rbac.ErrForbidden) {
		t.Fatalf("expected user with same ID to be forbidden due to type mismatch, got: %v", err)
	}
}

func TestSecurity_ConcurrentEvaluationAndMutations(t *testing.T) {
	ctx := context.Background()
	memCache := cache.NewMemoryCache(5 * time.Minute)

	_, rbacSvc := setupTestRBAC(t, rbac.WithCache(memCache))

	role := &rbac.Role{
		ID:          "role-concurrent",
		Name:        "concurrent_role",
		Scope:       rbac.ScopeGlobal,
		Permissions: []string{"data:read", "data:write"},
	}
	_ = rbacSvc.CreateRole(ctx, role)

	workers := 25
	var wg sync.WaitGroup

	// Concurrently assign, evaluate, and invalidate
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			user := auth.Principal{
				Subject: fmt.Sprintf("user-conc-%d", idx),
				Type:    auth.PrincipalUser,
			}
			assign := &rbac.RoleAssignment{
				ID:               fmt.Sprintf("asgn-%d", idx),
				RoleID:           role.ID,
				PrincipalSubject: user.Subject,
				PrincipalType:    user.Type,
				Scope:            rbac.ScopeGlobal,
			}

			_ = rbacSvc.AssignRole(ctx, assign)

			res := rbac.NewResource("data", fmt.Sprintf("%d", idx))
			_, _ = rbacSvc.IsAuthorized(ctx, user, "data:read", res)
			_ = rbacSvc.InvalidatePrincipalCache(ctx, user.Subject)
			_, _ = rbacSvc.Evaluate(ctx, user, "data:write", res)
		}(i)
	}

	wg.Wait()
}
