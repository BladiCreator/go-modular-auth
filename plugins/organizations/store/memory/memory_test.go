package memory_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth-organizations/store"
	"github.com/BladiCreator/go-modular-auth-organizations/store/memory"
)

func TestMemoryStoreConcurrency(t *testing.T) {
	ctx := context.Background()
	s := memory.New()

	org := &store.Organization{
		ID:        "org_conc",
		Name:      "Concurrent Org",
		Slug:      "conc-org",
		OwnerID:   "owner_conc",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := s.CreateOrganization(ctx, org); err != nil {
		t.Fatalf("CreateOrganization failed: %v", err)
	}

	const workers = 20
	var wg sync.WaitGroup

	// Concurrently add members
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			mem := &store.Membership{
				ID:             "mem_" + string(rune('A'+id)),
				OrganizationID: "org_conc",
				UserID:         "user_" + string(rune('A'+id)),
				Role:           store.RoleMember,
				Status:         store.MembershipActive,
				CreatedAt:      time.Now(),
				UpdatedAt:      time.Now(),
			}
			_ = s.CreateMembership(ctx, mem)
		}(i)
	}

	// Concurrently read
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = s.GetOrganizationByID(ctx, "org_conc")
			_, _ = s.ListMembershipsByOrg(ctx, "org_conc")
		}()
	}

	wg.Wait()

	members, err := s.ListMembershipsByOrg(ctx, "org_conc")
	if err != nil {
		t.Fatalf("ListMembershipsByOrg failed: %v", err)
	}
	if len(members) != workers {
		t.Errorf("Expected %d members, got %d", workers, len(members))
	}
}
