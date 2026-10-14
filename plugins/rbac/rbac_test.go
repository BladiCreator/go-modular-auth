package rbac_test

import (
	"context"
	"errors"
	"testing"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapter/memory"
	rbac "github.com/BladiCreator/go-modular-auth/plugins/rbac"
	"github.com/BladiCreator/go-modular-auth/plugins/rbac/cache"
)

func setupTestRBAC(t *testing.T, opts ...rbac.Option) (*auth.Auth, rbac.RBAC) {
	t.Helper()
	ad := adaptermem.New()
	plugin := rbac.New(opts...)

	a, err := auth.New(auth.Config{
		Adapter: ad,
		Plugins: []auth.PluginModule{plugin},
	})
	if err != nil {
		t.Fatalf("auth.New failed: %v", err)
	}

	rbacSvc, err := auth.Get[rbac.RBAC](a)
	if err != nil {
		t.Fatalf("auth.Get failed: %v", err)
	}

	return a, rbacSvc
}

func TestRBAC_RegistrationAndGlobalRoles(t *testing.T) {
	ctx := context.Background()
	memCache := cache.NewMemoryCache(10 * time.Minute)

	_, rbacSvc := setupTestRBAC(t, rbac.WithCache(memCache))

	// 1. Create a global superadmin role
	superAdminRole := &rbac.Role{
		ID:          "role-superadmin",
		Name:        "superadmin",
		Scope:       rbac.ScopeGlobal,
		Permissions: []string{"*"},
	}
	if err := rbacSvc.CreateRole(ctx, superAdminRole); err != nil {
		t.Fatalf("CreateRole failed: %v", err)
	}

	// 2. Assign role to global admin user
	adminPrincipal := auth.Principal{
		Subject: "user-super-1",
		Type:    auth.PrincipalUser,
	}
	err := rbacSvc.AssignRole(ctx, &rbac.RoleAssignment{
		RoleID:           superAdminRole.ID,
		PrincipalSubject: adminPrincipal.Subject,
		PrincipalType:    adminPrincipal.Type,
		Scope:            rbac.ScopeGlobal,
	})
	if err != nil {
		t.Fatalf("AssignRole failed: %v", err)
	}

	// 3. Superadmin can authorize any permission on any resource
	res := rbac.NewResource("document", "doc-123")
	if err := rbacSvc.Authorize(ctx, adminPrincipal, "documents:delete", res); err != nil {
		t.Fatalf("expected Authorize to succeed for superadmin, got: %v", err)
	}

	// Verify cached evaluation hit
	isAuth, err := rbacSvc.IsAuthorized(ctx, adminPrincipal, "documents:delete", res)
	if err != nil || !isAuth {
		t.Fatalf("expected IsAuthorized true, got isAuth=%v, err=%v", isAuth, err)
	}

	// 4. Regular unprivileged user is denied
	regularUser := auth.Principal{
		Subject: "user-regular-2",
		Type:    auth.PrincipalUser,
	}
	err = rbacSvc.Authorize(ctx, regularUser, "documents:delete", res)
	if !errors.Is(err, rbac.ErrForbidden) {
		t.Fatalf("expected ErrForbidden for unprivileged user, got: %v", err)
	}
}

func TestRBAC_OrganizationAndServiceRoles(t *testing.T) {
	ctx := context.Background()
	_, rbacSvc := setupTestRBAC(t)

	// 1. Create Organization Role
	orgBillingRole := &rbac.Role{
		ID:          "role-org-billing",
		Name:        "org_billing_admin",
		Scope:       rbac.ScopeOrganization,
		Permissions: []string{"invoices:view", "invoices:pay"},
	}
	if err := rbacSvc.CreateRole(ctx, orgBillingRole); err != nil {
		t.Fatalf("CreateRole failed: %v", err)
	}

	// 2. Assign to user scoped strictly to org-alpha
	userPrincipal := auth.Principal{Subject: "user-billing-1", Type: auth.PrincipalUser}
	err := rbacSvc.AssignRole(ctx, &rbac.RoleAssignment{
		RoleID:           orgBillingRole.ID,
		PrincipalSubject: userPrincipal.Subject,
		PrincipalType:    userPrincipal.Type,
		Scope:            rbac.ScopeOrganization,
		ScopeID:          "org-alpha",
	})
	if err != nil {
		t.Fatalf("AssignRole failed: %v", err)
	}

	// Evaluation 1: Resource belonging to org-alpha -> Authorized
	resOrgAlpha := rbac.NewOrganizationResource("invoice", "inv-100", "org-alpha")
	if err := rbacSvc.Authorize(ctx, userPrincipal, "invoices:pay", resOrgAlpha); err != nil {
		t.Fatalf("expected Authorize to succeed for org-alpha, got: %v", err)
	}

	// Evaluation 2: Resource belonging to org-beta -> Denied
	resOrgBeta := rbac.NewOrganizationResource("invoice", "inv-200", "org-beta")
	if err := rbacSvc.Authorize(ctx, userPrincipal, "invoices:pay", resOrgBeta); !errors.Is(err, rbac.ErrForbidden) {
		t.Fatalf("expected ErrForbidden for org-beta, got: %v", err)
	}

	// 3. Create Service-scoped Role for Microservice Auth
	svcWorkerRole := &rbac.Role{
		ID:          "role-svc-worker",
		Name:        "queue_worker",
		Scope:       rbac.ScopeService,
		Permissions: []string{"jobs:consume", "jobs:ack"},
	}
	if err := rbacSvc.CreateRole(ctx, svcWorkerRole); err != nil {
		t.Fatalf("CreateRole failed: %v", err)
	}

	svcPrincipal := auth.Principal{Subject: "worker-agent-1", Type: auth.PrincipalServiceAccount}
	err = rbacSvc.AssignRole(ctx, &rbac.RoleAssignment{
		RoleID:           svcWorkerRole.ID,
		PrincipalSubject: svcPrincipal.Subject,
		PrincipalType:    svcPrincipal.Type,
		Scope:            rbac.ScopeService,
		ScopeID:          "billing-service",
	})
	if err != nil {
		t.Fatalf("AssignRole failed: %v", err)
	}

	// Evaluation 3: Service Principal attempting billing-service action -> Authorized
	resService := rbac.NewServiceResource("job", "job-42", "billing-service")
	if err := rbacSvc.Authorize(ctx, svcPrincipal, "jobs:consume", resService); err != nil {
		t.Fatalf("expected Authorize to succeed for service, got: %v", err)
	}

	// Evaluation 4: Service Principal attempting another service -> Denied
	resOtherService := rbac.NewServiceResource("job", "job-99", "email-service")
	if err := rbacSvc.Authorize(ctx, svcPrincipal, "jobs:consume", resOtherService); !errors.Is(err, rbac.ErrForbidden) {
		t.Fatalf("expected ErrForbidden for wrong service, got: %v", err)
	}
}

func TestRBAC_WildcardPermissions(t *testing.T) {
	ctx := context.Background()
	_, rbacSvc := setupTestRBAC(t)

	editorRole := &rbac.Role{
		ID:          "role-editor",
		Name:        "editor",
		Scope:       rbac.ScopeGlobal,
		Permissions: []string{"articles:*", "media:upload"},
	}
	if err := rbacSvc.CreateRole(ctx, editorRole); err != nil {
		t.Fatalf("CreateRole failed: %v", err)
	}

	principal := auth.Principal{Subject: "editor-bob", Type: auth.PrincipalUser}
	_ = rbacSvc.AssignRole(ctx, &rbac.RoleAssignment{
		RoleID:           editorRole.ID,
		PrincipalSubject: principal.Subject,
		PrincipalType:    principal.Type,
		Scope:            rbac.ScopeGlobal,
	})

	res := rbac.NewResource("article", "art-1")

	// articles:create matches articles:*
	if err := rbacSvc.Authorize(ctx, principal, "articles:create", res); err != nil {
		t.Fatalf("expected articles:create to match articles:*, got: %v", err)
	}

	// articles:publish matches articles:*
	if err := rbacSvc.Authorize(ctx, principal, "articles:publish", res); err != nil {
		t.Fatalf("expected articles:publish to match articles:*, got: %v", err)
	}

	// media:upload is exact match
	if err := rbacSvc.Authorize(ctx, principal, "media:upload", res); err != nil {
		t.Fatalf("expected media:upload to match, got: %v", err)
	}

	// media:delete is not granted
	if err := rbacSvc.Authorize(ctx, principal, "media:delete", res); !errors.Is(err, rbac.ErrForbidden) {
		t.Fatalf("expected media:delete to be forbidden, got: %v", err)
	}
}

func TestRBAC_CacheInvalidationOnMutation(t *testing.T) {
	ctx := context.Background()
	memCache := cache.NewMemoryCache(1 * time.Hour)

	_, rbacSvc := setupTestRBAC(t, rbac.WithCache(memCache))

	role := &rbac.Role{
		ID:          "role-temp",
		Name:        "temp_role",
		Scope:       rbac.ScopeGlobal,
		Permissions: []string{"temp:view"},
	}
	_ = rbacSvc.CreateRole(ctx, role)

	principal := auth.Principal{Subject: "user-cache-1", Type: auth.PrincipalUser}
	assign := &rbac.RoleAssignment{
		ID:               "asgn-temp-1",
		RoleID:           role.ID,
		PrincipalSubject: principal.Subject,
		PrincipalType:    principal.Type,
		Scope:            rbac.ScopeGlobal,
	}
	_ = rbacSvc.AssignRole(ctx, assign)

	res := rbac.NewResource("temp", "1")

	// 1. Authorize: primes the cache with true
	if err := rbacSvc.Authorize(ctx, principal, "temp:view", res); err != nil {
		t.Fatalf("Authorize failed: %v", err)
	}

	// 2. Revoke role assignment -> invalidates principal cache
	if err := rbacSvc.RevokeRole(ctx, assign.ID); err != nil {
		t.Fatalf("RevokeRole failed: %v", err)
	}

	// 3. Now Authorize MUST be denied because cache was invalidated and assignment is gone!
	if err := rbacSvc.Authorize(ctx, principal, "temp:view", res); !errors.Is(err, rbac.ErrForbidden) {
		t.Fatalf("expected ErrForbidden after role revocation, got: %v", err)
	}
}

func TestRBAC_ContextualOrganizationEvaluation(t *testing.T) {
	ctx := context.Background()
	_, rbacSvc := setupTestRBAC(t)

	// 1. Create organization-scoped role
	role := &rbac.Role{
		ID:          "role-org-admin",
		Name:        "billing_admin",
		Scope:       rbac.ScopeOrganization,
		Permissions: []string{"billing:view", "billing:update"},
	}
	if err := rbacSvc.CreateRole(ctx, role); err != nil {
		t.Fatalf("CreateRole failed: %v", err)
	}

	principal := auth.Principal{Subject: "finance-carol", Type: auth.PrincipalUser}

	// 2. Assign role to principal specifically in "org-acme"
	err := rbacSvc.AssignRole(ctx, &rbac.RoleAssignment{
		RoleID:           role.ID,
		PrincipalSubject: principal.Subject,
		PrincipalType:    principal.Type,
		Scope:            rbac.ScopeOrganization,
		ScopeID:          "org-acme",
	})
	if err != nil {
		t.Fatalf("AssignRole failed: %v", err)
	}

	// 3. Evaluation without organization context fails
	emptyRes := rbac.NewResource("invoice", "inv-1")
	if err := rbacSvc.Authorize(ctx, principal, "billing:view", emptyRes); !errors.Is(err, rbac.ErrForbidden) {
		t.Fatalf("expected ErrForbidden without org context, got %v", err)
	}

	// 4. Evaluation with context-bound organization succeeds automatically
	acmeCtx := auth.WithOrganization(ctx, "org-acme")
	if err := rbacSvc.Authorize(acmeCtx, principal, "billing:view", emptyRes); err != nil {
		t.Fatalf("expected success with contextual org-acme, got: %v", err)
	}

	// 5. Evaluation with a different organization in context fails
	otherCtx := auth.WithOrganization(ctx, "org-other")
	if err := rbacSvc.Authorize(otherCtx, principal, "billing:view", emptyRes); !errors.Is(err, rbac.ErrForbidden) {
		t.Fatalf("expected ErrForbidden with wrong org context, got %v", err)
	}
}
