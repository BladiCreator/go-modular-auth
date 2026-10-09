package scim_test

import (
	"context"
	"testing"

	auth "github.com/BladiCreator/go-modular-auth"
	storememory "github.com/BladiCreator/go-modular-auth/store/memory"
	scim "github.com/BladiCreator/go-modular-auth-scim"
	v2 "github.com/BladiCreator/go-modular-auth-scim/v2"
)

func TestSCIMProvider_UserAndGroupProvisioning(t *testing.T) {
	ctx := context.Background()
	mod := scim.New()

	a, err := auth.New(auth.Config{
		Store:   storememory.New(),
		Plugins: []auth.PluginModule{mod},
	})
	if err != nil {
		t.Fatalf("failed to create auth engine: %v", err)
	}

	provider, err := auth.Get[scim.SCIMProvider](a)
	if err != nil {
		t.Fatalf("failed to get SCIMProvider: %v", err)
	}

	// 1. Create user
	createdUser, err := provider.CreateUser(ctx, &v2.UserResource{
		UserName:   "charlie@enterprise.com",
		ExternalID: "okta-usr-99",
		Active:     true,
		Name: &v2.Name{
			GivenName:  "Charlie",
			FamilyName: "Brown",
		},
	})
	if err != nil {
		t.Fatalf("failed to create SCIM user: %v", err)
	}
	if createdUser.ID == "" || createdUser.ExternalID != "okta-usr-99" {
		t.Errorf("unexpected user resource: %+v", createdUser)
	}

	// 2. Get user
	fetchedUser, err := provider.GetUser(ctx, createdUser.ID)
	if err != nil {
		t.Fatalf("failed to fetch SCIM user: %v", err)
	}
	if fetchedUser.UserName != "charlie@enterprise.com" {
		t.Errorf("expected userName charlie@enterprise.com, got %s", fetchedUser.UserName)
	}

	// 3. Create group with member
	group, err := provider.CreateGroup(ctx, &v2.GroupResource{
		DisplayName: "Engineers",
		Members: []v2.GroupMember{
			{Value: createdUser.ID},
		},
	})
	if err != nil {
		t.Fatalf("failed to create SCIM group: %v", err)
	}
	if group.ID == "" || group.DisplayName != "Engineers" || len(group.Members) != 1 {
		t.Errorf("unexpected group resource: %+v", group)
	}

	// 4. List groups
	listResp, err := provider.ListGroups(ctx, 1, 10)
	if err != nil {
		t.Fatalf("failed to list groups: %v", err)
	}
	if listResp.TotalResults != 1 {
		t.Errorf("expected 1 group, got %d", listResp.TotalResults)
	}

	// 5. Delete user and group
	if err := provider.DeleteUser(ctx, createdUser.ID); err != nil {
		t.Fatalf("failed to delete user: %v", err)
	}
	if err := provider.DeleteGroup(ctx, group.ID); err != nil {
		t.Fatalf("failed to delete group: %v", err)
	}
}
