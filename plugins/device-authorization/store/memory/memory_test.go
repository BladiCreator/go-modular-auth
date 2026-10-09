package memory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth-device-authorization/store"
	"github.com/BladiCreator/go-modular-auth-device-authorization/store/memory"
)

func TestMemoryStore_Lifecycle(t *testing.T) {
	ctx := context.Background()
	s := memory.New()

	now := time.Now()
	grant := &store.DeviceGrant{
		ID:              "grant_1",
		ClientID:        "client_tv",
		DeviceCodeHash:  "hash_123456",
		UserCode:        "WDJB-MJHT",
		Status:          store.StatusPending,
		Scope:           "openid profile",
		ExpiresAt:       now.Add(10 * time.Minute),
		PollingInterval: 5,
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	// 1. Create
	if err := s.Create(ctx, grant); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Duplicate create should return ErrConflict
	if err := s.Create(ctx, grant); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("expected ErrConflict on duplicate create, got %v", err)
	}

	// 2. GetByDeviceCodeHash
	byHash, err := s.GetByDeviceCodeHash(ctx, "hash_123456")
	if err != nil {
		t.Fatalf("GetByDeviceCodeHash failed: %v", err)
	}
	if byHash.ID != "grant_1" || byHash.UserCode != "WDJB-MJHT" {
		t.Fatalf("unexpected grant: %+v", byHash)
	}

	// 3. GetByUserCode
	byCode, err := s.GetByUserCode(ctx, "wdjb-mjht") // case-insensitive lookup
	if err != nil {
		t.Fatalf("GetByUserCode failed: %v", err)
	}
	if byCode.ID != "grant_1" {
		t.Fatalf("unexpected grant: %+v", byCode)
	}

	// 4. Update
	byCode.Status = store.StatusAuthorized
	byCode.UserID = "usr_100"
	if err := s.Update(ctx, byCode); err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	updated, _ := s.GetByDeviceCodeHash(ctx, "hash_123456")
	if updated.Status != store.StatusAuthorized || updated.UserID != "usr_100" {
		t.Fatalf("unexpected updated grant: %+v", updated)
	}

	// 5. IncrementFailedAttempts
	attempts, err := s.IncrementFailedAttempts(ctx, "WDJB-MJHT")
	if err != nil || attempts != 1 {
		t.Fatalf("IncrementFailedAttempts failed: attempts=%d, err=%v", attempts, err)
	}

	// 6. Delete
	if err := s.Delete(ctx, "grant_1"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	_, err = s.GetByDeviceCodeHash(ctx, "hash_123456")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
}

func TestMemoryStore_TransactionRollback(t *testing.T) {
	ctx := context.Background()
	s := memory.New()

	now := time.Now()
	grant := &store.DeviceGrant{
		ID:              "grant_tx",
		ClientID:        "client_tx",
		DeviceCodeHash:  "hash_tx",
		UserCode:        "TX01-TX02",
		Status:          store.StatusPending,
		ExpiresAt:       now.Add(5 * time.Minute),
		PollingInterval: 5,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	_ = s.Create(ctx, grant)

	errAbort := errors.New("aborted")
	err := s.Transaction(ctx, func(txCtx context.Context) error {
		g, _ := s.GetByUserCode(txCtx, "TX01-TX02")
		g.Status = store.StatusAuthorized
		_ = s.Update(txCtx, g)
		return errAbort
	})

	if !errors.Is(err, errAbort) {
		t.Fatalf("expected errAbort, got %v", err)
	}

	// Verify rollback preserved previous status
	g, err := s.GetByUserCode(ctx, "TX01-TX02")
	if err != nil {
		t.Fatalf("GetByUserCode failed: %v", err)
	}
	if g.Status != store.StatusPending {
		t.Fatalf("expected StatusPending after rollback, got %v", g.Status)
	}
}

func TestMemoryStore_DeleteExpired(t *testing.T) {
	ctx := context.Background()
	s := memory.New()

	past := time.Now().Add(-10 * time.Minute)
	future := time.Now().Add(10 * time.Minute)

	_ = s.Create(ctx, &store.DeviceGrant{
		ID:             "exp_1",
		ClientID:       "client_exp",
		DeviceCodeHash: "hash_exp",
		UserCode:       "EXP1-0001",
		ExpiresAt:      past,
	})
	_ = s.Create(ctx, &store.DeviceGrant{
		ID:             "live_1",
		ClientID:       "client_live",
		DeviceCodeHash: "hash_live",
		UserCode:       "LIVE-0001",
		ExpiresAt:      future,
	})

	deleted, err := s.DeleteExpired(ctx, time.Now())
	if err != nil || deleted != 1 {
		t.Fatalf("DeleteExpired expected 1, got %d, err=%v", deleted, err)
	}

	_, err = s.GetByUserCode(ctx, "EXP1-0001")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected expired grant deleted, got %v", err)
	}

	_, err = s.GetByUserCode(ctx, "LIVE-0001")
	if err != nil {
		t.Fatalf("expected live grant preserved, got %v", err)
	}
}
