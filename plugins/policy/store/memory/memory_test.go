package memory_test

import (
	"context"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth-policy/store"
	"github.com/BladiCreator/go-modular-auth-policy/store/memory"
)

func TestMemoryStore_Lifecycle(t *testing.T) {
	ctx := context.Background()
	s := memory.NewStore()

	rec := &store.PolicyRecord{
		ID:          "pol-1",
		Description: "Admin Policy",
		Combinator:  "deny_overrides",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := s.SavePolicyRecord(ctx, rec); err != nil {
		t.Fatalf("SavePolicyRecord failed: %v", err)
	}

	got, err := s.GetPolicyRecord(ctx, "pol-1")
	if err != nil {
		t.Fatalf("GetPolicyRecord failed: %v", err)
	}
	if got.Description != "Admin Policy" {
		t.Fatalf("unexpected record: %+v", got)
	}

	list, err := s.ListPolicyRecords(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("ListPolicyRecords failed: %v, len=%d", err, len(list))
	}

	if err := s.DeletePolicyRecord(ctx, "pol-1"); err != nil {
		t.Fatalf("DeletePolicyRecord failed: %v", err)
	}

	_, err = s.GetPolicyRecord(ctx, "pol-1")
	if err == nil {
		t.Fatal("expected error after delete, got nil")
	}
}
