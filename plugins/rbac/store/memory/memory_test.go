package memory_test

import (
	"context"
	"testing"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth-rbac/store"
	"github.com/BladiCreator/go-modular-auth-rbac/store/memory"
)

func TestMemoryStore_RolesLifecycle(t *testing.T) {
	ctx := context.Background()
	s := memory.NewStore()

	role := &store.Role{
		ID:          "role-1",
		Name:        "admin",
		Description: "Administrator",
		Scope:       store.ScopeGlobal,
		Permissions: []string{"users:read", "users:write"},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := s.CreateRole(ctx, role); err != nil {
		t.Fatalf("CreateRole failed: %v", err)
	}

	// Duplicate ID or Name should fail
	if err := s.CreateRole(ctx, role); err == nil {
		t.Fatal("expected error on duplicate role, got nil")
	}

	got, err := s.GetRole(ctx, "role-1")
	if err != nil {
		t.Fatalf("GetRole failed: %v", err)
	}
	if got.Name != "admin" || len(got.Permissions) != 2 {
		t.Fatalf("unexpected role content: %+v", got)
	}

	byName, err := s.GetRoleByName(ctx, "admin")
	if err != nil {
		t.Fatalf("GetRoleByName failed: %v", err)
	}
	if byName.ID != "role-1" {
		t.Fatalf("unexpected role ID: %s", byName.ID)
	}

	// Update role
	got.Description = "Updated Admin"
	got.Permissions = []string{"*"}
	if err := s.UpdateRole(ctx, got); err != nil {
		t.Fatalf("UpdateRole failed: %v", err)
	}

	updated, err := s.GetRole(ctx, "role-1")
	if err != nil {
		t.Fatalf("GetRole after update failed: %v", err)
	}
	if updated.Description != "Updated Admin" || len(updated.Permissions) != 1 {
		t.Fatalf("update was not persisted properly: %+v", updated)
	}

	// List roles
	list, err := s.ListRoles(ctx, store.ScopeGlobal)
	if err != nil || len(list) != 1 {
		t.Fatalf("ListRoles failed or returned invalid count: %v, len=%d", err, len(list))
	}

	// Delete role
	if err := s.DeleteRole(ctx, "role-1"); err != nil {
		t.Fatalf("DeleteRole failed: %v", err)
	}
	if _, err := s.GetRole(ctx, "role-1"); err == nil {
		t.Fatal("expected ErrNotFound after deletion, got nil")
	}
}

func TestMemoryStore_AssignmentsLifecycle(t *testing.T) {
	ctx := context.Background()
	s := memory.NewStore()

	assign := &store.RoleAssignment{
		ID:               "assign-1",
		RoleID:           "role-admin",
		PrincipalSubject: "user-123",
		PrincipalType:    auth.PrincipalUser,
		Scope:            store.ScopeOrganization,
		ScopeID:          "org-456",
		CreatedAt:        time.Now(),
	}

	if err := s.CreateAssignment(ctx, assign); err != nil {
		t.Fatalf("CreateAssignment failed: %v", err)
	}

	// Duplicate assignment
	if err := s.CreateAssignment(ctx, assign); err == nil {
		t.Fatal("expected duplicate assignment to fail, got nil")
	}

	list, err := s.ListAssignmentsByPrincipal(ctx, "user-123", auth.PrincipalUser)
	if err != nil || len(list) != 1 {
		t.Fatalf("ListAssignmentsByPrincipal failed: %v, len=%d", err, len(list))
	}

	byRole, err := s.ListAssignmentsByRole(ctx, "role-admin")
	if err != nil || len(byRole) != 1 {
		t.Fatalf("ListAssignmentsByRole failed: %v, len=%d", err, len(byRole))
	}

	if err := s.DeleteAssignment(ctx, "assign-1"); err != nil {
		t.Fatalf("DeleteAssignment failed: %v", err)
	}

	afterDelete, _ := s.ListAssignmentsByPrincipal(ctx, "user-123", auth.PrincipalUser)
	if len(afterDelete) != 0 {
		t.Fatalf("expected 0 assignments, got %d", len(afterDelete))
	}
}
