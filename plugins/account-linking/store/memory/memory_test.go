package memory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth-account-linking/store"
	"github.com/BladiCreator/go-modular-auth-account-linking/store/memory"
)

func TestMemoryStore_Lifecycle(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	now := time.Now().UTC()

	ticket := &store.LinkingTicket{
		ID:             "t_1",
		TokenHash:      "hash_1",
		UserID:         "u_1",
		TargetProvider: "google",
		ExpiresAt:      now.Add(10 * time.Minute),
		CreatedAt:      now,
	}

	// 1. Save
	if err := s.SaveTicket(ctx, ticket); err != nil {
		t.Fatalf("SaveTicket failed: %v", err)
	}

	// 2. Conflict on duplicate
	if err := s.SaveTicket(ctx, ticket); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("expected ErrConflict, got: %v", err)
	}

	// 3. Get
	got, err := s.GetTicketByHash(ctx, "hash_1")
	if err != nil || got == nil {
		t.Fatalf("GetTicketByHash failed: %v", err)
	}
	if got.UserID != "u_1" || got.TargetProvider != "google" {
		t.Fatalf("unexpected ticket: %+v", got)
	}

	// 4. Consume
	consumed, err := s.ConsumeTicket(ctx, "hash_1", now.Add(1*time.Minute))
	if err != nil || consumed == nil || consumed.ConsumedAt == nil {
		t.Fatalf("ConsumeTicket failed: %v", err)
	}

	// 5. Consume again must fail
	_, err = s.ConsumeTicket(ctx, "hash_1", now.Add(2*time.Minute))
	if !errors.Is(err, store.ErrTicketConsumed) {
		t.Fatalf("expected ErrTicketConsumed, got: %v", err)
	}

	// 6. Delete
	if err := s.DeleteTicket(ctx, "t_1"); err != nil {
		t.Fatalf("DeleteTicket failed: %v", err)
	}
	_, err = s.GetTicketByHash(ctx, "hash_1")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got: %v", err)
	}
}

func TestMemoryStore_PurgeExpired(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	now := time.Now().UTC()

	_ = s.SaveTicket(ctx, &store.LinkingTicket{
		ID:        "t_exp",
		TokenHash: "h_exp",
		UserID:    "u_1",
		ExpiresAt: now.Add(-5 * time.Minute),
		CreatedAt: now.Add(-10 * time.Minute),
	})
	_ = s.SaveTicket(ctx, &store.LinkingTicket{
		ID:        "t_act",
		TokenHash: "h_act",
		UserID:    "u_2",
		ExpiresAt: now.Add(10 * time.Minute),
		CreatedAt: now,
	})

	count, err := s.PurgeExpiredTickets(ctx, now)
	if err != nil {
		t.Fatalf("PurgeExpiredTickets failed: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 purged, got %d", count)
	}

	_, err = s.GetTicketByHash(ctx, "h_act")
	if err != nil {
		t.Errorf("active ticket should still exist: %v", err)
	}
}
