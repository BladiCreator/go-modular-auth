package cache_test

import (
	"context"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth-admin/cache"
	corecache "github.com/BladiCreator/go-modular-auth/cache/memory"
)

func TestCache_DisabledFlag(t *testing.T) {
	ctx := context.Background()
	coreMem := corecache.New()
	c := cache.New(coreMem)

	userID := "usr_cached_1"

	// 1. Initial lookup -> miss
	dis, found, err := c.GetDisabled(ctx, userID)
	if err != nil {
		t.Fatalf("GetDisabled failed: %v", err)
	}
	if found {
		t.Fatalf("expected not found initially, got true")
	}

	// 2. SetDisabled true
	if err := c.SetDisabled(ctx, userID, true, 10*time.Minute); err != nil {
		t.Fatalf("SetDisabled failed: %v", err)
	}

	// 3. GetDisabled -> hit
	dis, found, err = c.GetDisabled(ctx, userID)
	if err != nil || !found || !dis {
		t.Fatalf("expected found=true, disabled=true, got found=%v, dis=%v, err=%v", found, dis, err)
	}

	// 4. DeleteDisabled -> miss
	if err := c.DeleteDisabled(ctx, userID); err != nil {
		t.Fatalf("DeleteDisabled failed: %v", err)
	}
	_, found, err = c.GetDisabled(ctx, userID)
	if err != nil || found {
		t.Fatalf("expected found=false after delete, got found=%v, err=%v", found, err)
	}
}

func TestCache_AdminFlag(t *testing.T) {
	ctx := context.Background()
	coreMem := corecache.New()
	c := cache.New(coreMem)

	userID := "usr_admin_cached"

	if err := c.SetIsAdmin(ctx, userID, true, 5*time.Minute); err != nil {
		t.Fatalf("SetIsAdmin failed: %v", err)
	}

	isAdmin, found, err := c.GetIsAdmin(ctx, userID)
	if err != nil || !found || !isAdmin {
		t.Fatalf("expected found=true, isAdmin=true, got found=%v, isAdmin=%v, err=%v", found, isAdmin, err)
	}

	if err := c.DeleteIsAdmin(ctx, userID); err != nil {
		t.Fatalf("DeleteIsAdmin failed: %v", err)
	}

	_, found, err = c.GetIsAdmin(ctx, userID)
	if err != nil || found {
		t.Fatalf("expected found=false after delete, got %v", found)
	}
}
