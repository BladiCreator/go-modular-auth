package cache_test

import (
	"context"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth-organizations/cache"
	"github.com/BladiCreator/go-modular-auth-organizations/store"
	corecache "github.com/BladiCreator/go-modular-auth/cache/memory"
)

func TestCacheOperations(t *testing.T) {
	ctx := context.Background()
	core := corecache.New()
	c := cache.New(core)

	if !c.Available() {
		t.Fatal("Expected cache to be available")
	}

	org := &store.Organization{
		ID:        "org_123",
		Name:      "Test Org",
		Slug:      "test-org",
		OwnerID:   "owner_123",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// 1. Set and Get Organization by ID
	if err := c.SetOrganization(ctx, org, 1*time.Minute); err != nil {
		t.Fatalf("SetOrganization failed: %v", err)
	}

	cached, err := c.GetOrganizationByID(ctx, "org_123")
	if err != nil {
		t.Fatalf("GetOrganizationByID failed: %v", err)
	}
	if cached.ID != "org_123" || cached.Slug != "test-org" {
		t.Errorf("Unexpected cached org: %+v", cached)
	}

	// 2. Get Organization by Slug
	bySlug, err := c.GetOrganizationBySlug(ctx, "test-org")
	if err != nil {
		t.Fatalf("GetOrganizationBySlug failed: %v", err)
	}
	if bySlug.ID != "org_123" {
		t.Errorf("Expected org_123, got %s", bySlug.ID)
	}

	// 3. Delete Organization
	if err := c.DeleteOrganization(ctx, "org_123", "test-org"); err != nil {
		t.Fatalf("DeleteOrganization failed: %v", err)
	}
	_, err = c.GetOrganizationByID(ctx, "org_123")
	if err == nil {
		t.Fatal("Expected cache miss after deletion, got hit")
	}
	_, err = c.GetOrganizationBySlug(ctx, "test-org")
	if err == nil {
		t.Fatal("Expected cache miss for slug after deletion, got hit")
	}

	// 4. Membership cache
	mem := &store.Membership{
		ID:             "mem_123",
		OrganizationID: "org_123",
		UserID:         "user_123",
		Role:           store.RoleMember,
		Status:         store.MembershipActive,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}
	if err := c.SetMembership(ctx, mem, 1*time.Minute); err != nil {
		t.Fatalf("SetMembership failed: %v", err)
	}

	cachedMem, err := c.GetMembership(ctx, "org_123", "user_123")
	if err != nil {
		t.Fatalf("GetMembership failed: %v", err)
	}
	if cachedMem.Role != store.RoleMember {
		t.Errorf("Unexpected membership role: %s", cachedMem.Role)
	}

	// Invalidate membership
	if err := c.DeleteMembership(ctx, "org_123", "user_123"); err != nil {
		t.Fatalf("DeleteMembership failed: %v", err)
	}
	_, err = c.GetMembership(ctx, "org_123", "user_123")
	if err == nil {
		t.Fatal("Expected cache miss for membership after deletion, got hit")
	}
}

func TestNilCacheOperations(t *testing.T) {
	ctx := context.Background()
	c := cache.New(nil)

	if c.Available() {
		t.Fatal("Expected nil cache not to be available")
	}

	// Operations should safely no-op
	if err := c.SetOrganization(ctx, &store.Organization{ID: "1"}, 1*time.Minute); err != nil {
		t.Errorf("Expected nil error on nil cache, got %v", err)
	}
	if _, err := c.GetOrganizationByID(ctx, "1"); err == nil {
		t.Error("Expected error from nil cache lookup")
	}
}
