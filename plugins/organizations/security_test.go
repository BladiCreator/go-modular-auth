package organizations_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapter/memory"
	"github.com/BladiCreator/go-modular-auth/plugins/organizations"
)

func TestSecurityCrossTenantIsolation(t *testing.T) {
	ctx := context.Background()
	orgModule := organizations.New()
	a, _ := auth.New(auth.Config{
		Adapter: adaptermem.New(),
		Plugins: []auth.PluginModule{orgModule},
	})
	orgs, _ := auth.Get[organizations.Organization](a)

	// Org A
	orgA, _ := orgs.CreateOrganization(ctx, organizations.CreateOrganizationInput{
		Name:    "Tenant A",
		Slug:    "tenant-a",
		OwnerID: "user_a",
	})
	teamA, _ := orgs.CreateTeam(ctx, organizations.CreateTeamInput{
		OrganizationID: orgA.ID,
		Name:           "Security Team",
		Slug:           "security",
	})

	// Org B
	orgB, _ := orgs.CreateOrganization(ctx, organizations.CreateOrganizationInput{
		Name:    "Tenant B",
		Slug:    "tenant-b",
		OwnerID: "user_b",
	})

	// User B trying to access Org A's team in Org B must fail
	_, err := orgs.GetTeam(ctx, orgB.ID, teamA.ID)
	if err == nil {
		t.Fatal("Tenant B was able to fetch Tenant A team! Isolation violated")
	}

	// User B trying to enroll in Org A's team must fail
	err = orgs.AddTeamMember(ctx, orgA.ID, teamA.ID, "user_b")
	if err == nil {
		t.Fatal("Tenant B user was able to enroll in Tenant A team! Isolation violated")
	}

	// User B trying to authorize with Org A with active Principal
	userBCtx := auth.WithPrincipal(ctx, auth.Principal{Subject: "user_b", Type: auth.PrincipalUser})
	_, err = orgs.Authorize(userBCtx, orgA.ID, organizations.RoleMember)
	if err == nil {
		t.Fatal("Tenant B user authorized in Tenant A! Isolation violated")
	}
}

func TestSecurityInvitationSingleUseAndConcurrency(t *testing.T) {
	ctx := context.Background()
	orgModule := organizations.New()
	a, _ := auth.New(auth.Config{
		Adapter: adaptermem.New(),
		Plugins: []auth.PluginModule{orgModule},
	})
	orgs, _ := auth.Get[organizations.Organization](a)

	org, _ := orgs.CreateOrganization(ctx, organizations.CreateOrganizationInput{
		Name:    "FinTech Org",
		Slug:    "fintech",
		OwnerID: "fin_owner",
	})

	_, token, _ := orgs.CreateInvitation(ctx, organizations.CreateInvitationInput{
		OrganizationID: org.ID,
		Email:          "singleuse@example.com",
		Role:           organizations.RoleMember,
		InviterUserID:  "fin_owner",
		TTL:            1 * time.Hour,
	})

	// Race condition test: 10 concurrent redemption requests with different user IDs
	const concurrency = 10
	var wg sync.WaitGroup
	var successCount int
	var mu sync.Mutex

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			mem, err := orgs.AcceptInvitation(ctx, token, "user_concurrent_"+string(rune('A'+id)))
			if err == nil && mem != nil {
				mu.Lock()
				successCount++
				mu.Unlock()
			}
		}(i)
	}

	wg.Wait()

	if successCount != 1 {
		t.Fatalf("Expected exactly 1 concurrent invitation redemption to succeed, got %d", successCount)
	}
}

func TestSecurityInvitationExpiration(t *testing.T) {
	ctx := context.Background()
	orgModule := organizations.New()
	a, _ := auth.New(auth.Config{
		Adapter: adaptermem.New(),
		Plugins: []auth.PluginModule{orgModule},
	})
	orgs, _ := auth.Get[organizations.Organization](a)

	org, _ := orgs.CreateOrganization(ctx, organizations.CreateOrganizationInput{
		Name:    "Expired Inc",
		Slug:    "expired-inc",
		OwnerID: "exp_owner",
	})

	// Create already expired invitation
	_, token, _ := orgs.CreateInvitation(ctx, organizations.CreateInvitationInput{
		OrganizationID: org.ID,
		Email:          "expired@example.com",
		Role:           organizations.RoleMember,
		InviterUserID:  "exp_owner",
		TTL:            -1 * time.Second, // Already expired
	})

	_, err := orgs.AcceptInvitation(ctx, token, "user_exp")
	if err == nil {
		t.Fatal("Expected ErrInvitationExpired, got nil")
	}
}

func TestSecurityConstantTimeComparison(t *testing.T) {
	h1 := organizations.HashToken("secure-random-token-1")
	h2 := organizations.HashToken("secure-random-token-1")
	h3 := organizations.HashToken("secure-random-token-2")

	if !organizations.ConstantTimeCompare(h1, h2) {
		t.Error("Expected identical hashes to compare true")
	}
	if organizations.ConstantTimeCompare(h1, h3) {
		t.Error("Expected different hashes to compare false")
	}
}

func TestOrganizationService_UnauthorizedMutationRejection(t *testing.T) {
	ctx := context.Background()
	orgModule := organizations.New()
	a, _ := auth.New(auth.Config{
		Adapter: adaptermem.New(),
		Plugins: []auth.PluginModule{orgModule},
	})
	orgs, _ := auth.Get[organizations.Organization](a)

	// 1. Create Organization with owner_user
	org, err := orgs.CreateOrganization(ctx, organizations.CreateOrganizationInput{
		Name:    "Secure Corp",
		Slug:    "secure-corp",
		OwnerID: "owner_user",
	})
	if err != nil {
		t.Fatalf("CreateOrganization failed: %v", err)
	}

	// 2. Add an admin and a regular member
	_, err = orgs.AddMember(ctx, organizations.AddMemberInput{
		OrganizationID: org.ID,
		UserID:         "admin_user",
		Role:           organizations.RoleAdmin,
	})
	if err != nil {
		t.Fatalf("AddMember admin failed: %v", err)
	}

	_, err = orgs.AddMember(ctx, organizations.AddMemberInput{
		OrganizationID: org.ID,
		UserID:         "regular_member",
		Role:           organizations.RoleMember,
	})
	if err != nil {
		t.Fatalf("AddMember regular failed: %v", err)
	}

	memberCtx := auth.WithPrincipal(ctx, auth.Principal{Subject: "regular_member", Type: auth.PrincipalUser})
	adminCtx := auth.WithPrincipal(ctx, auth.Principal{Subject: "admin_user", Type: auth.PrincipalUser})
	outsiderCtx := auth.WithPrincipal(ctx, auth.Principal{Subject: "outsider_user", Type: auth.PrincipalUser})
	ownerCtx := auth.WithPrincipal(ctx, auth.Principal{Subject: "owner_user", Type: auth.PrincipalUser})

	// Test A: Outsider cannot mutate anything
	_, err = orgs.UpdateOrganization(outsiderCtx, org.ID, organizations.UpdateOrganizationInput{})
	if !errors.Is(err, organizations.ErrUnauthorized) {
		t.Fatalf("Expected ErrUnauthorized for outsider UpdateOrganization, got %v", err)
	}

	// Test B: Regular member cannot perform admin mutations
	_, err = orgs.AddMember(memberCtx, organizations.AddMemberInput{
		OrganizationID: org.ID,
		UserID:         "intruder",
	})
	if !errors.Is(err, organizations.ErrUnauthorized) {
		t.Fatalf("Expected ErrUnauthorized for regular member AddMember, got %v", err)
	}

	_, err = orgs.UpdateMemberRole(memberCtx, org.ID, "regular_member", organizations.RoleOwner)
	if !errors.Is(err, organizations.ErrUnauthorized) {
		t.Fatalf("Expected ErrUnauthorized for member escalating own role, got %v", err)
	}

	err = orgs.DeleteOrganization(memberCtx, org.ID)
	if !errors.Is(err, organizations.ErrUnauthorized) {
		t.Fatalf("Expected ErrUnauthorized for member deleting organization, got %v", err)
	}

	// Test C: Admin cannot delete organization or transfer ownership (owner only)
	err = orgs.DeleteOrganization(adminCtx, org.ID)
	if !errors.Is(err, organizations.ErrUnauthorized) {
		t.Fatalf("Expected ErrUnauthorized for admin deleting organization, got %v", err)
	}

	err = orgs.TransferOwnership(adminCtx, org.ID, "admin_user")
	if !errors.Is(err, organizations.ErrUnauthorized) {
		t.Fatalf("Expected ErrUnauthorized for admin transferring ownership, got %v", err)
	}

	// Test D: Admin cannot change Owner's role
	_, err = orgs.UpdateMemberRole(adminCtx, org.ID, "owner_user", organizations.RoleMember)
	if !errors.Is(err, organizations.ErrUnauthorized) {
		t.Fatalf("Expected ErrUnauthorized for admin demoting owner, got %v", err)
	}

	// Test E: Authorized operations succeed
	newName := "Secure Corp Renamed"
	updated, err := orgs.UpdateOrganization(adminCtx, org.ID, organizations.UpdateOrganizationInput{
		Name: &newName,
	})
	if err != nil {
		t.Fatalf("Admin UpdateOrganization failed: %v", err)
	}
	if updated.Name != newName {
		t.Errorf("Expected updated name %s, got %s", newName, updated.Name)
	}

	// Test F: Owner can transfer ownership
	err = orgs.TransferOwnership(ownerCtx, org.ID, "admin_user")
	if err != nil {
		t.Fatalf("Owner TransferOwnership failed: %v", err)
	}
}
