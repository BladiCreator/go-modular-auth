package admin_test

import (
	"testing"

	"github.com/BladiCreator/go-modular-auth/plugins/admin"
)

func TestDefaultRoles(t *testing.T) {
	roles := admin.DefaultRoles()

	adminRole, ok := roles[admin.RoleAdmin]
	if !ok {
		t.Fatalf("expected admin role to be defined in DefaultRoles")
	}

	if len(adminRole.Statements[admin.ResourceUser]) == 0 {
		t.Errorf("expected admin role to have user statements")
	}
	if len(adminRole.Statements[admin.ResourceSession]) == 0 {
		t.Errorf("expected admin role to have session statements")
	}

	userRole, ok := roles[admin.RoleUser]
	if !ok {
		t.Fatalf("expected user role to be defined in DefaultRoles")
	}
	if len(userRole.Statements) != 0 {
		t.Errorf("expected user role to have empty statements by default")
	}
}

func TestRole_Authorize(t *testing.T) {
	adminRole := admin.Role{
		Name: "admin",
		Statements: admin.Statements{
			admin.ResourceUser:    {admin.ActionCreate, admin.ActionList, admin.ActionBan},
			admin.ResourceSession: {admin.ActionSessionRevoke},
		},
	}

	res := adminRole.Authorize(admin.Permissions{
		admin.ResourceUser: {admin.ActionCreate, admin.ActionBan},
	}, admin.ConnectorAND)
	if !res.Success {
		t.Errorf("expected Authorize to succeed for admin role, got error: %s", res.Error)
	}

	resFail := adminRole.Authorize(admin.Permissions{
		admin.ResourceUser: {admin.ActionCreate, admin.ActionDelete},
	}, admin.ConnectorAND)
	if resFail.Success {
		t.Errorf("expected Authorize to fail when an action is missing")
	}

	resOR := adminRole.Authorize(admin.Permissions{
		admin.ResourceUser: {admin.ActionDelete, admin.ActionCreate},
	}, admin.ConnectorOR)
	if !resOR.Success {
		t.Errorf("expected Authorize with ConnectorOR to succeed when one action matches")
	}

	resORFail := adminRole.Authorize(admin.Permissions{
		admin.ResourceUser: {"non_existent_action"},
	}, admin.ConnectorOR)
	if resORFail.Success {
		t.Errorf("expected Authorize with ConnectorOR to fail when no actions match")
	}

	var nilRole *admin.Role
	nilRes := nilRole.Authorize(admin.Permissions{admin.ResourceUser: {admin.ActionCreate}}, admin.ConnectorAND)
	if nilRes.Success {
		t.Errorf("expected nil role to fail authorization")
	}
}

func TestAccessControlRegistry(t *testing.T) {
	ac := admin.NewAccessControl()

	if _, ok := ac.GetRole(admin.RoleAdmin); !ok {
		t.Errorf("expected default admin role in registry")
	}
	if _, ok := ac.GetRole(admin.RoleUser); !ok {
		t.Errorf("expected default user role in registry")
	}

	custom := admin.Role{
		Name: "moderator",
		Statements: admin.Statements{
			admin.ResourceUser: {admin.ActionBan, admin.ActionList},
		},
	}
	ac.RegisterRole(custom)

	r, ok := ac.GetRole("moderator")
	if !ok {
		t.Fatalf("expected moderator role to be retrieved")
	}
	if len(r.Statements[admin.ResourceUser]) != 2 {
		t.Errorf("expected 2 statements for moderator, got %d", len(r.Statements[admin.ResourceUser]))
	}

	allRoles := ac.Roles()
	if len(allRoles) < 3 {
		t.Errorf("expected at least 3 roles in registry, got %d", len(allRoles))
	}
}

func TestHasPermission(t *testing.T) {
	customRoles := map[string]admin.Role{
		"auditor": {
			Name: "auditor",
			Statements: admin.Statements{
				admin.ResourceUser:    {admin.ActionList, admin.ActionGet},
				admin.ResourceSession: {admin.ActionSessionList},
			},
		},
		"operator": {
			Name: "operator",
			Statements: admin.Statements{
				admin.ResourceUser: {admin.ActionBan},
			},
		},
		"superstar": {
			Name: "superstar",
			Statements: admin.Statements{
				"*": {"*"},
			},
		},
	}

	t.Run("AdminUserIDs bypass", func(t *testing.T) {
		allowed := admin.HasPermission(admin.HasPermissionInput{
			UserID:       "usr_superadmin",
			Role:         "user",
			AdminUserIDs: []string{"usr_superadmin", "usr_owner"},
			Permissions: admin.Permissions{
				admin.ResourceUser: {admin.ActionDelete, admin.ActionBan},
			},
			Connector: admin.ConnectorAND,
		})
		if !allowed {
			t.Errorf("expected AdminUserIDs bypass to grant permission")
		}
	})

	t.Run("Empty permissions request returns true", func(t *testing.T) {
		allowed := admin.HasPermission(admin.HasPermissionInput{
			UserID:      "usr_regular",
			Role:        "user",
			Permissions: admin.Permissions{},
		})
		if !allowed {
			t.Errorf("expected empty permissions check to return true")
		}
	})

	t.Run("Built-in admin role allows admin actions", func(t *testing.T) {
		allowed := admin.HasPermission(admin.HasPermissionInput{
			UserID: "usr_admin",
			Role:   "admin",
			Permissions: admin.Permissions{
				admin.ResourceUser:    {admin.ActionCreate, admin.ActionBan},
				admin.ResourceSession: {admin.ActionSessionRevoke},
			},
			Connector: admin.ConnectorAND,
		})
		if !allowed {
			t.Errorf("expected admin role to have create/ban/revoke permissions")
		}
	})

	t.Run("Built-in user role is denied admin actions", func(t *testing.T) {
		allowed := admin.HasPermission(admin.HasPermissionInput{
			UserID: "usr_user",
			Role:   "user",
			Permissions: admin.Permissions{
				admin.ResourceUser: {admin.ActionBan},
			},
			Connector: admin.ConnectorAND,
		})
		if allowed {
			t.Errorf("expected regular user to be denied ban action")
		}
	})

	t.Run("Fallback to default role when role is empty", func(t *testing.T) {
		allowed := admin.HasPermission(admin.HasPermissionInput{
			UserID:      "usr_blank",
			Role:        "",
			DefaultRole: "admin",
			Permissions: admin.Permissions{
				admin.ResourceUser: {admin.ActionList},
			},
			Connector: admin.ConnectorAND,
		})
		if !allowed {
			t.Errorf("expected fallback to default role 'admin' to succeed")
		}
	})

	t.Run("Compound roles separated by comma", func(t *testing.T) {
		allowed := admin.HasPermission(admin.HasPermissionInput{
			UserID:      "usr_multi",
			Role:        "auditor, operator",
			RolesConfig: customRoles,
			Permissions: admin.Permissions{
				admin.ResourceUser: {admin.ActionList, admin.ActionBan},
			},
			Connector: admin.ConnectorAND,
		})
		if !allowed {
			t.Errorf("expected compound role 'auditor, operator' to satisfy both list and ban")
		}
	})

	t.Run("Wildcard resource and action support", func(t *testing.T) {
		allowed := admin.HasPermission(admin.HasPermissionInput{
			UserID:      "usr_superstar",
			Role:        "superstar",
			RolesConfig: customRoles,
			Permissions: admin.Permissions{
				"custom_resource": {"any_action", "another_action"},
			},
			Connector: admin.ConnectorAND,
		})
		if !allowed {
			t.Errorf("expected wildcard role to grant any permission")
		}
	})

	t.Run("ConnectorOR evaluation", func(t *testing.T) {
		allowed := admin.HasPermission(admin.HasPermissionInput{
			UserID:      "usr_auditor",
			Role:        "auditor",
			RolesConfig: customRoles,
			Permissions: admin.Permissions{
				admin.ResourceUser: {admin.ActionDelete, admin.ActionList},
			},
			Connector: admin.ConnectorOR,
		})
		if !allowed {
			t.Errorf("expected ConnectorOR to succeed when auditor has ActionList")
		}
	})
}
