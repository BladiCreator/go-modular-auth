package access_test

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	"github.com/BladiCreator/go-modular-auth/plugin"
	"github.com/BladiCreator/go-modular-auth/plugins"
	"github.com/BladiCreator/go-modular-auth/plugins/access"
	"github.com/asaskevich/EventBus"
)

// Master statement schema matching standard Better Auth test fixture
var testMasterStatements = access.Statements{
	"project": {"create", "read", "update", "delete"},
	"user":    {"create", "read", "update", "delete"},
	"billing": {"view", "manage"},
}

// -----------------------------------------------------------------------------
// 1. Better Auth TypeScript 100% Parity Tests
// -----------------------------------------------------------------------------

func TestBetterAuthParity_RoleCreationAndStatements(t *testing.T) {
	ac := access.CreateAccessControl(testMasterStatements)

	userRole, err := ac.NewRole("user", access.Statements{
		"project": {"create", "read"},
	})
	if err != nil {
		t.Fatalf("unexpected error creating role: %v", err)
	}

	if userRole.Name() != "user" {
		t.Errorf("expected role name 'user', got '%s'", userRole.Name())
	}

	stmts := userRole.Statements()
	if len(stmts["project"]) != 2 {
		t.Errorf("expected 2 actions for project, got %d", len(stmts["project"]))
	}
}

func TestBetterAuthParity_SingleAndMultipleActions(t *testing.T) {
	ac := access.CreateAccessControl(testMasterStatements)
	role := ac.MustNewRole("editor", access.Statements{
		"project": {"create", "read", "update"},
		"user":    {"read"},
	})

	// Single action check
	res := role.Authorize(access.Req("project", "create"))
	if !res.Success {
		t.Errorf("expected success for single action, got error: %s", res.Error)
	}

	// Single action helper
	if !role.HasPermission("project", "read") {
		t.Errorf("expected HasPermission to return true for project read")
	}

	// Multiple actions check (AND)
	res = role.Authorize(access.Req("project", "create", "read", "update"))
	if !res.Success {
		t.Errorf("expected success for multiple actions (AND), got error: %s", res.Error)
	}

	// Multiple actions check failing under AND
	res = role.Authorize(access.Req("project", "create", "delete"))
	if res.Success {
		t.Errorf("expected failure when requesting delete action")
	}
	expectedErr := access.ErrPrefixUnauthorized + `"project"`
	if res.Error != expectedErr {
		t.Errorf("expected error '%s', got '%s'", expectedErr, res.Error)
	}
}

func TestBetterAuthParity_ResourceLevelOR(t *testing.T) {
	ac := access.CreateAccessControl(testMasterStatements)
	role := ac.MustNewRole("reader_or_creator", access.Statements{
		"project": {"read"},
	})

	// Request has delete (missing) OR read (present) -> should succeed
	res := role.Authorize(access.ReqOR("project", "delete", "read"))
	if !res.Success {
		t.Errorf("expected success under resource-level OR, got error: %s", res.Error)
	}

	// Request has delete OR create (both missing) -> should fail
	res = role.Authorize(access.ReqOR("project", "delete", "create"))
	if res.Success {
		t.Errorf("expected failure when none of the OR actions match")
	}
	expectedErr := access.ErrPrefixUnauthorized + `"project"`
	if res.Error != expectedErr {
		t.Errorf("expected error '%s', got '%s'", expectedErr, res.Error)
	}
}

func TestBetterAuthParity_MultiResource_AND(t *testing.T) {
	ac := access.CreateAccessControl(testMasterStatements)
	role := ac.MustNewRole("manager", access.Statements{
		"project": {"create", "read"},
		"user":    {"read"},
	})

	// Both satisfied
	req := access.NewAuthorizeRequest().
		Require("project", "create").
		Require("user", "read").
		Build()

	res := role.Authorize(req, access.ConnectorAND)
	if !res.Success {
		t.Errorf("expected success for multi-resource AND, got error: %s", res.Error)
	}

	// One resource fails action check
	reqFail := access.NewAuthorizeRequest().
		Require("project", "create").
		Require("user", "delete").
		Build()

	resFail := role.Authorize(reqFail, access.ConnectorAND)
	if resFail.Success {
		t.Errorf("expected failure for unsatisfied resource in AND")
	}
	expectedErr := access.ErrPrefixUnauthorized + `"user"`
	if resFail.Error != expectedErr {
		t.Errorf("expected error '%s', got '%s'", expectedErr, resFail.Error)
	}
}

func TestBetterAuthParity_MultiResource_OR(t *testing.T) {
	ac := access.CreateAccessControl(testMasterStatements)
	role := ac.MustNewRole("auditor", access.Statements{
		"user": {"read"},
	})

	// project is unknown to this role, but user is authorized -> under global OR it should succeed!
	req := access.NewAuthorizeRequest().
		Require("project", "delete").
		Require("user", "read").
		Build()

	res := role.Authorize(req, access.ConnectorOR)
	if !res.Success {
		t.Errorf("expected success under global OR when one resource matches, got: %s", res.Error)
	}

	// Neither matches -> fails with "Not authorized"
	reqNone := access.NewAuthorizeRequest().
		Require("project", "delete").
		Require("billing", "manage").
		Build()

	resNone := role.Authorize(reqNone, access.ConnectorOR)
	if resNone.Success {
		t.Errorf("expected failure when no resources match under global OR")
	}
	if resNone.Error != access.ErrMsgNotAuthorized {
		t.Errorf("expected error '%s', got '%s'", access.ErrMsgNotAuthorized, resNone.Error)
	}
}

func TestBetterAuthParity_EmptyActionsRejected(t *testing.T) {
	ac := access.CreateAccessControl(testMasterStatements)
	role := ac.MustNewRole("admin", access.Statements{
		"project": {"create", "read"},
	})

	// Request with empty actions [] must fail
	req := access.AuthorizeRequest{
		"project": access.ActionRequest{
			Actions:   []string{},
			Connector: access.ConnectorAND,
		},
	}

	res := role.Authorize(req)
	if res.Success {
		t.Errorf("expected authorization failure for empty actions request")
	}
	expectedErr := access.ErrPrefixUnauthorized + `"project"`
	if res.Error != expectedErr {
		t.Errorf("expected error '%s', got '%s'", expectedErr, res.Error)
	}

	// Under OR with all empty actions -> must fail
	reqOR := access.AuthorizeRequest{
		"project": access.ActionRequest{
			Actions:   []string{},
			Connector: access.ConnectorOR,
		},
	}
	resOR := role.Authorize(reqOR, access.ConnectorOR)
	if resOR.Success {
		t.Errorf("expected authorization failure for empty actions under global OR")
	}
	if resOR.Error != access.ErrMsgNotAuthorized {
		t.Errorf("expected error '%s', got '%s'", access.ErrMsgNotAuthorized, resOR.Error)
	}
}

func TestBetterAuthParity_UnknownResourceError(t *testing.T) {
	ac := access.CreateAccessControl(testMasterStatements)
	role := ac.MustNewRole("limited", access.Statements{
		"user": {"read"},
	})

	// Unknown resource under ConnectorAND
	res := role.Authorize(access.Req("unknown_resource", "create"), access.ConnectorAND)
	if res.Success {
		t.Errorf("expected failure for unknown resource")
	}
	expectedErr := access.ErrPrefixUnknownResource + "unknown_resource"
	if res.Error != expectedErr {
		t.Errorf("expected error '%s', got '%s'", expectedErr, res.Error)
	}
}

func TestBetterAuthParity_EmptyRequest(t *testing.T) {
	ac := access.CreateAccessControl(testMasterStatements)
	role := ac.MustNewRole("admin", access.Statements{
		"project": {"*"},
	})

	res := role.Authorize(access.AuthorizeRequest{})
	if res.Success {
		t.Errorf("expected failure for empty request")
	}
	if res.Error != access.ErrMsgNotAuthorized {
		t.Errorf("expected error '%s', got '%s'", access.ErrMsgNotAuthorized, res.Error)
	}
	if res.Err() == nil {
		t.Errorf("expected res.Err() to return non-nil error")
	}
}

// -----------------------------------------------------------------------------
// 2. Go Ecosystem Extensions & Multi-Role Tests
// -----------------------------------------------------------------------------

func TestAccessControl_MultiRoleEvaluation(t *testing.T) {
	ac := access.CreateAccessControl(testMasterStatements)

	ac.MustNewRole("project_viewer", access.Statements{
		"project": {"read"},
	})
	ac.MustNewRole("user_manager", access.Statements{
		"user": {"create", "read", "update", "delete"},
	})

	// User has both roles
	roles := []string{"project_viewer", "user_manager"}
	req := access.NewAuthorizeRequest().
		Require("project", "read").
		Require("user", "create").
		Build()

	res := ac.AuthorizeRoles(roles, req)
	if !res.Success {
		t.Errorf("expected success for multi-role evaluation, got error: %s", res.Error)
	}

	// Comma-separated string support
	resStr := ac.AuthorizeRoleString("project_viewer, user_manager", req)
	if !resStr.Success {
		t.Errorf("expected success for comma-separated role string, got error: %s", resStr.Error)
	}

	// Non-existent role evaluation
	resNone := ac.AuthorizeRoles([]string{"non_existent"}, req)
	if resNone.Success {
		t.Errorf("expected failure for non-existent role")
	}
}

func TestAccessControl_RoleExtensionAndCloning(t *testing.T) {
	ac := access.CreateAccessControl(testMasterStatements)

	baseRole := ac.MustNewRole("member", access.Statements{
		"project": {"read"},
	})

	// Extend role without mutating baseRole
	leadRole := baseRole.Extend("lead", access.Statements{
		"project": {"create", "update"},
		"billing": {"view"},
	})

	if leadRole.Name() != "lead" {
		t.Errorf("expected lead role name 'lead', got '%s'", leadRole.Name())
	}

	// Verify baseRole statements remain untouched
	if baseRole.HasPermission("project", "create") {
		t.Errorf("baseRole should not have project:create permission")
	}

	// Verify leadRole has combined permissions
	if !leadRole.HasPermission("project", "read") || !leadRole.HasPermission("project", "create") || !leadRole.HasPermission("billing", "view") {
		t.Errorf("leadRole should have all inherited and additional permissions")
	}

	// Test Cloning
	cloned := leadRole.Clone("lead_copy")
	if cloned.Name() != "lead_copy" {
		t.Errorf("expected clone name 'lead_copy', got '%s'", cloned.Name())
	}
	if !cloned.HasPermission("project", "create") {
		t.Errorf("cloned role should have same permissions")
	}
}

func TestAccessControl_MergeRoles(t *testing.T) {
	ac := access.CreateAccessControl(testMasterStatements)

	ac.MustNewRole("role_a", access.Statements{"project": {"read"}})
	ac.MustNewRole("role_b", access.Statements{"user": {"read"}})

	merged, err := ac.MergeRoles("role_a", "role_b")
	if err != nil {
		t.Fatalf("unexpected error merging roles: %v", err)
	}

	if !merged.HasPermission("project", "read") || !merged.HasPermission("user", "read") {
		t.Errorf("merged role should satisfy both role_a and role_b permissions")
	}

	// Merging non-existent role fails
	_, err = ac.MergeRoles("role_a", "non_existent")
	if err == nil {
		t.Errorf("expected error when merging non-existent role")
	}
}

func TestAccessControl_Wildcards(t *testing.T) {
	ac := access.CreateAccessControl(testMasterStatements, access.WithAllowWildcards(true))

	// 1. Superadmin with "*": ["*"]
	superAdmin := ac.MustNewRole("superadmin", access.Statements{
		"*": {"*"},
	})
	if !superAdmin.HasPermission("any_resource", "any_action") {
		t.Errorf("superadmin wildcard should grant any resource and action")
	}

	// 2. Resource wildcard: "project": ["*"]
	projectAdmin := ac.MustNewRole("project_admin", access.Statements{
		"project": {"*"},
	})
	if !projectAdmin.HasPermission("project", "custom_action_xyz") {
		t.Errorf("project admin wildcard should grant all actions for project")
	}
	if projectAdmin.HasPermission("user", "read") {
		t.Errorf("project admin should not have access to user resource")
	}

	// 3. Action wildcard: "*": ["read"]
	globalReader := ac.MustNewRole("global_reader", access.Statements{
		"*": {"read"},
	})
	if !globalReader.HasPermission("project", "read") || !globalReader.HasPermission("user", "read") {
		t.Errorf("global reader should have read access to any resource")
	}
	if globalReader.HasPermission("project", "delete") {
		t.Errorf("global reader should not have delete permission")
	}
}

func TestAccessControl_StrictResources(t *testing.T) {
	ac := access.CreateAccessControl(testMasterStatements,
		access.WithStrictResources(true),
		access.WithAllowWildcards(false),
	)

	// Valid role
	_, err := ac.NewRole("valid", access.Statements{
		"project": {"read", "create"},
	})
	if err != nil {
		t.Errorf("unexpected error creating valid role in strict mode: %v", err)
	}

	// Invalid resource
	_, err = ac.NewRole("invalid_res", access.Statements{
		"undefined_resource": {"read"},
	})
	if err == nil {
		t.Errorf("expected error creating role with undefined resource in strict mode")
	}

	// Invalid action for resource
	_, err = ac.NewRole("invalid_act", access.Statements{
		"project": {"unsupported_action"},
	})
	if err == nil {
		t.Errorf("expected error creating role with unsupported action in strict mode")
	}
}

func TestAccessControl_DynamicRoleManagement(t *testing.T) {
	ac := access.CreateAccessControl(testMasterStatements)

	_, err := ac.NewRole("temp", access.Statements{"project": {"read"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := ac.GetRole("temp"); !ok {
		t.Errorf("expected GetRole to find 'temp'")
	}

	all := ac.GetAllRoles()
	if _, ok := all["temp"]; !ok {
		t.Errorf("expected GetAllRoles to contain 'temp'")
	}

	deleted := ac.DeleteRole("temp")
	if !deleted {
		t.Errorf("expected DeleteRole to return true")
	}

	if _, ok := ac.GetRole("temp"); ok {
		t.Errorf("expected GetRole to not find deleted role")
	}
}

func TestRole_JSONSerialization(t *testing.T) {
	role := access.NewRole("moderator", access.Statements{
		"user":    {"read", "update"},
		"project": {"read"},
	}, true)

	data, err := json.Marshal(role)
	if err != nil {
		t.Fatalf("failed to marshal role: %v", err)
	}

	var restored access.Role
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("failed to unmarshal role: %v", err)
	}

	if restored.Name() != "moderator" {
		t.Errorf("expected name 'moderator', got '%s'", restored.Name())
	}
	if !restored.HasPermission("user", "update") || !restored.HasPermission("project", "read") {
		t.Errorf("restored role does not match original permissions")
	}
}

func TestAccessControl_Concurrency(t *testing.T) {
	ac := access.CreateAccessControl(testMasterStatements, access.WithAllowWildcards(true))
	ac.MustNewRole("base_reader", access.Statements{"project": {"read"}})

	var wg sync.WaitGroup
	workers := 20
	iterations := 100

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			roleName := fmt.Sprintf("dynamic_role_%d", workerID)

			for j := 0; j < iterations; j++ {
				// Write
				_, _ = ac.NewRole(roleName, access.Statements{"project": {"read", "update"}})

				// Read
				r, ok := ac.GetRole(roleName)
				if ok {
					_ = r.HasPermission("project", "read")
					_ = r.Authorize(access.Req("project", "update"))
				}

				// Multi-role evaluation
				_ = ac.AuthorizeRoles([]string{"base_reader", roleName}, access.Req("project", "read"))

				// Delete periodically
				if j%20 == 0 {
					ac.DeleteRole(roleName)
				}
			}
		}(i)
	}

	wg.Wait()
}

// -----------------------------------------------------------------------------
// 3. Guards and Context Helpers Tests
// -----------------------------------------------------------------------------

func TestAccessGuards_ContextIntegration(t *testing.T) {
	ac := access.CreateAccessControl(testMasterStatements)
	ac.MustNewRole("admin", access.Statements{"project": {"create", "read", "delete"}})
	ac.MustNewRole("viewer", access.Statements{"project": {"read"}})

	guard := access.RequirePermission(ac, access.ContextRoleResolver, "project", "create")

	// Context with viewer role -> Denied
	viewerCtx := access.WithSubjectRoles(context.Background(), "viewer")
	if err := guard(viewerCtx); err == nil {
		t.Errorf("expected viewer to be denied for project:create")
	}

	// Context with admin role -> Allowed
	adminCtx := access.WithSubjectRoles(context.Background(), "admin")
	if err := guard(adminCtx); err != nil {
		t.Errorf("expected admin to be authorized for project:create, got error: %v", err)
	}

	// Direct AuthorizeSubject helper
	req := access.Req("project", "delete")
	res := access.AuthorizeSubject(adminCtx, ac, access.ContextRoleResolver, req)
	if !res.Success {
		t.Errorf("expected AuthorizeSubject to succeed for admin")
	}
}

// -----------------------------------------------------------------------------
// 4. Plugin Lifecycle and Factory Tests
// -----------------------------------------------------------------------------

func TestPlugin_LifecycleAndEvents(t *testing.T) {
	bus := EventBus.New()
	ctx := plugin.NewContext(nil, bus)

	accessPlugin := plugins.Access(
		testMasterStatements,
		access.WithInitialRoles(map[string]access.Statements{
			"admin": {"*": {"*"}},
		}),
	)

	if accessPlugin.ID() != "access" {
		t.Errorf("expected plugin ID 'access', got '%s'", accessPlugin.ID())
	}

	if err := accessPlugin.Init(ctx); err != nil {
		t.Fatalf("failed to init access plugin: %v", err)
	}

	// Verify retrieval from context
	val, ok := ctx.Get(access.ContextKeyAccessControl)
	if !ok || val == nil {
		t.Fatalf("expected AccessControl in context store")
	}

	ac, ok := val.(*access.AccessControl)
	if !ok || ac == nil {
		t.Fatalf("expected value in context to be *access.AccessControl")
	}

	// Test Event subscriptions
	var authorizedEventReceived bool
	_ = bus.Subscribe(access.EventAccessAuthorized, func(p *access.AccessAuthorizedEventPayload) {
		authorizedEventReceived = true
		if len(p.Roles) == 0 || p.Roles[0] != "admin" {
			t.Errorf("unexpected roles in event payload: %v", p.Roles)
		}
	})

	accessPlugin.PublishAuthorized([]string{"admin"}, access.Req("project", "create"), map[string]any{"user_id": "usr_123"})

	if !authorizedEventReceived {
		t.Errorf("expected EventAccessAuthorized to be dispatched and received")
	}
}
