package organizations_test

import (
	"context"
	"sync"
	"testing"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth-organizations"
	"github.com/BladiCreator/go-modular-auth-organizations/store/memory"
	coremem "github.com/BladiCreator/go-modular-auth/store/memory"
)

func TestSecurityCrossTenantIsolation(t *testing.T) {
	ctx := context.Background()
	orgModule := organizations.New(organizations.WithStore(memory.New()))
	a, _ := auth.New(auth.Config{
		Store:   coremem.New(),
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
	orgModule := organizations.New(organizations.WithStore(memory.New()))
	a, _ := auth.New(auth.Config{
		Store:   coremem.New(),
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
	orgModule := organizations.New(organizations.WithStore(memory.New()))
	a, _ := auth.New(auth.Config{
		Store:   coremem.New(),
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
