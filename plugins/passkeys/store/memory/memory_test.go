package memory_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth-passkeys/store"
	"github.com/BladiCreator/go-modular-auth-passkeys/store/memory"
)

func TestMemoryStore(t *testing.T) {
	ctx := context.Background()
	s := memory.New()

	cred := &store.Credential{
		ID:           "test_cred_id_1",
		CredentialID: []byte("raw_cred_1"),
		UserID:       "user_123",
		FriendlyName: "Work Laptop",
		PublicKey:    []byte("cose_pub_key"),
		AAGUID:       []byte("00000000-0000-0000-0000-000000000000"),
		SignCount:    1,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	// 1. Save
	if err := s.SaveCredential(ctx, cred); err != nil {
		t.Fatalf("unexpected error saving: %v", err)
	}

	// 2. Duplicate conflict
	if err := s.SaveCredential(ctx, cred); err != store.ErrConflict {
		t.Fatalf("expected ErrConflict, got %v", err)
	}

	// 3. Get by ID
	got, err := s.GetCredentialByID(ctx, []byte("raw_cred_1"))
	if err != nil {
		t.Fatalf("unexpected error getting: %v", err)
	}
	if got.UserID != "user_123" || got.FriendlyName != "Work Laptop" {
		t.Fatalf("mismatched credential: %+v", got)
	}

	// 4. List by user
	list, err := s.ListCredentialsByUser(ctx, "user_123")
	if err != nil {
		t.Fatalf("unexpected error listing: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(list))
	}

	// 5. Update
	got.FriendlyName = "Personal Laptop"
	got.SignCount = 2
	if err := s.UpdateCredential(ctx, got); err != nil {
		t.Fatalf("unexpected error updating: %v", err)
	}
	updated, err := s.GetCredentialByID(ctx, []byte("raw_cred_1"))
	if err != nil {
		t.Fatalf("unexpected error getting updated: %v", err)
	}
	if updated.FriendlyName != "Personal Laptop" || updated.SignCount != 2 {
		t.Fatalf("expected updated fields, got %+v", updated)
	}

	// 6. Delete
	if err := s.DeleteCredential(ctx, []byte("raw_cred_1")); err != nil {
		t.Fatalf("unexpected error deleting: %v", err)
	}
	if _, err := s.GetCredentialByID(ctx, []byte("raw_cred_1")); err != store.ErrNotFound {
		t.Fatalf("expected ErrNotFound after deletion, got %v", err)
	}
}

func TestMemoryStoreConcurrency(t *testing.T) {
	ctx := context.Background()
	s := memory.New()

	var wg sync.WaitGroup
	workers := 20

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			cred := &store.Credential{
				ID:           string(rune('a' + id)),
				CredentialID: []byte{byte(id)},
				UserID:       "concurrent_user",
				FriendlyName: "Key",
				CreatedAt:    time.Now(),
				UpdatedAt:    time.Now(),
			}
			_ = s.SaveCredential(ctx, cred)
			_, _ = s.GetCredentialByID(ctx, []byte{byte(id)})
			_, _ = s.ListCredentialsByUser(ctx, "concurrent_user")
		}(i)
	}

	wg.Wait()

	list, err := s.ListCredentialsByUser(ctx, "concurrent_user")
	if err != nil {
		t.Fatalf("failed listing concurrent credentials: %v", err)
	}
	if len(list) != workers {
		t.Fatalf("expected %d credentials, got %d", workers, len(list))
	}
}
