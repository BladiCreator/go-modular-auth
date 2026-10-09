package memory_test

import (
	"context"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth-password-policy/store"
	"github.com/BladiCreator/go-modular-auth-password-policy/store/memory"
)

func TestMemoryStore_HistoryLifecycle(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	now := time.Now().UTC()

	// Save 4 history items for u1
	for i := 1; i <= 4; i++ {
		err := s.SaveHistory(ctx, &store.PasswordHistory{
			ID:           time.Now().Format("20060102150405.000000"),
			UserID:       "u1",
			PasswordHash: "hash_" + string(rune('0'+i)),
			CreatedAt:    now.Add(time.Duration(i) * time.Minute),
		})
		if err != nil {
			t.Fatalf("SaveHistory %d failed: %v", i, err)
		}
	}

	// Retrieve top 3
	list, err := s.GetHistory(ctx, "u1", 3)
	if err != nil {
		t.Fatalf("GetHistory failed: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("expected 3 items, got %d", len(list))
	}
	// Newest first -> hash_4
	if list[0].PasswordHash != "hash_4" {
		t.Errorf("expected newest first (hash_4), got %s", list[0].PasswordHash)
	}

	// Prune to 2
	if err := s.PruneHistory(ctx, "u1", 2); err != nil {
		t.Fatalf("PruneHistory failed: %v", err)
	}
	allRemaining, _ := s.GetHistory(ctx, "u1", 10)
	if len(allRemaining) != 2 {
		t.Fatalf("expected 2 items after prune, got %d", len(allRemaining))
	}

	// Delete all
	if err := s.DeleteHistoryByUser(ctx, "u1"); err != nil {
		t.Fatalf("DeleteHistoryByUser failed: %v", err)
	}
	empty, _ := s.GetHistory(ctx, "u1", 10)
	if len(empty) != 0 {
		t.Errorf("expected 0 items after delete, got %d", len(empty))
	}
}
