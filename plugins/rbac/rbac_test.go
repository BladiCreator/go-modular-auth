package rbac_test

import (
	"context"
	"errors"
	"testing"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapters/memory"
	rbac "github.com/BladiCreator/go-modular-auth-rbac"
	"github.com/BladiCreator/go-modular-auth-rbac/cache"
	"github.com/BladiCreator/go-modular-auth-rbac/store/memory"
)

func TestRBAC_RegistrationAndGlobalRoles(t *testing.T) {
	ctx := context.Background()
	coreStore := adaptermem.NewStore()
	rbacStore := memory.NewStore()
	memCache := cache.NewMemoryCache(10 * time.Minute)

	plugin := rbac.New(
		rbac.WithStore(rbacStore),
		rbac.WithCache(memCache),
	)

	a, err := auth.New(auth.Config{
		Store:   coreStore,
		Plugins: []auth.PluginModule{plugin},
	})
	if err != nil {
		t.Fatalf("auth.New failed: %v", err)
	}

	rbacSvc, err := auth.Get[rbac.RBAC](a)
	if err != nil {
		t.Fatalf("auth.Get failed: %v", err)
	}

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
	err = rbacSvc.AssignRole(ctx, &rbac.RoleAssignment{
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
	coreStore := adaptermem.NewStore()
	rbacStore := memory.NewStore()

	plugin := rbac.New(rbac.WithStore(rbacStore))

	a, err := auth.New(auth.Config{
		Store:   coreStore,
		Plugins: []auth.PluginModule{plugin},
	})
	if err != nil {
		t.Fatalf("auth.New failed: %v", err)
	}

	rbacSvc, err := auth.Get[rbac.RBAC](a)
	if err != nil {
		t.Fatalf("auth.Get failed: %v", err)
	}

	// 1. Create Organization Role
	orgBillingRole := &rbac.Role{
		ID:          "role-org-billing",
		Name:        "org_billing_admin",
		Scope:       rbac.ScopeOrganization,
		Permissions: []string{"invoices:view", "invoices:pay"},
	}
	if err := rbacSvc.CreateRole(ctx, orgBillingRole); err != nil {
		t.Fatalf("CreateRole org failed: %v", err)
	}

	// 2. Create Service Role
	svcJobRole := &rbac.Role{
		ID:          "role-svc-worker",
		Name:        "service_worker",
		Scope:       rbac.ScopeService,
		Permissions: []string{"jobs:consume", "jobs:complete"},
	}
	if err := rbacSvc.CreateRole(ctx, svcJobRole); err != nil {
		t.Fatalf("CreateRole svc failed: %v", err)
	}

	// 3. Assign to user in Org Alpha
	userAlpha := auth.Principal{Subject: "user-alpha", Type: auth.PrincipalUser}
	err = rbacSvc.AssignRole(ctx, &rbac.RoleAssignment{
		RoleID:           orgBillingRole.ID,
		PrincipalSubject: userAlpha.Subject,
		PrincipalType:    userAlpha.Type,
		Scope:            rbac.ScopeOrganization,
		ScopeID:          "org-alpha",
	})
	if err != nil {
		t.Fatalf("AssignRole org failed: %v", err)
	}

	// 4. Assign Service role to service account
	svcPrincipal := auth.Principal{Subject: "svc-crawler", Type: auth.PrincipalServiceAccount}
	err = rbacSvc.AssignRole(ctx, &rbac.RoleAssignment{
		RoleID:           svcJobRole.ID,
		PrincipalSubject: svcPrincipal.Subject,
		PrincipalType:    svcPrincipal.Type,
		Scope:            rbac.ScopeService,
		ScopeID:          "queue-service",
	})
	if err != nil {
		t.Fatalf("AssignRole svc failed: %v", err)
	}

	// Evaluation 1: User Alpha in Org Alpha accessing Invoice in Org Alpha -> Allowed
	resAlpha := rbac.NewOrganizationResource("invoice", "inv-001", "org-alpha")
	if err := rbacSvc.Authorize(ctx, userAlpha, "invoices:pay", resAlpha); err != nil {
		t.Fatalf("expected userAlpha to be authorized in org-alpha, got: %v", err)
	}

	// Evaluation 2: User Alpha attempting to access Org Beta -> Denied
	resBeta := rbac.NewOrganizationResource("invoice", "inv-002", "org-beta")
	if err := rbacSvc.Authorize(ctx, userAlpha, "invoices:pay", resBeta); !errors.Is(err, rbac.ErrForbidden) {
		t.Fatalf("expected ErrForbidden for cross-org access, got: %v", err)
	}

	// Evaluation 3: Service Principal in queue-service -> Allowed
	resQueue := rbac.NewServiceResource("job", "job-99", "queue-service")
	if err := rbacSvc.Authorize(ctx, svcPrincipal, "jobs:consume", resQueue); err != nil {
		t.Fatalf("expected svcPrincipal to be authorized in queue-service, got: %v", err)
	}

	// Evaluation 4: Service Principal attempting another service -> Denied
	resOtherService := rbac.NewServiceResource("job", "job-99", "email-service")
	if err := rbacSvc.Authorize(ctx, svcPrincipal, "jobs:consume", resOtherService); !errors.Is(err, rbac.ErrForbidden) {
		t.Fatalf("expected ErrForbidden for wrong service, got: %v", err)
	}
}

func TestRBAC_WildcardPermissions(t *testing.T) {
	ctx := context.Background()
	rbacStore := memory.NewStore()
	plugin := rbac.New(rbac.WithStore(rbacStore))

	a, err := auth.New(auth.Config{
		Store:   adaptermem.NewStore(),
		Plugins: []auth.PluginModule{plugin},
	})
	if err != nil {
		t.Fatalf("auth.New failed: %v", err)
	}

	rbacSvc, err := auth.Get[rbac.RBAC](a)
	if err != nil {
		t.Fatalf("auth.Get failed: %v", err)
	}

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
	rbacStore := memory.NewStore()
	memCache := cache.NewMemoryCache(1 * time.Hour)

	plugin := rbac.New(
		rbac.WithStore(rbacStore),
		rbac.WithCache(memCache),
	)

	a, err := auth.New(auth.Config{
		Store:   adaptermem.NewStore(),
		Plugins: []auth.PluginModule{plugin},
	})
	if err != nil {
		t.Fatalf("auth.New failed: %v", err)
	}

	rbacSvc, err := auth.Get[rbac.RBAC](a)
	if err != nil {
		t.Fatalf("auth.Get failed: %v", err)
	}

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
