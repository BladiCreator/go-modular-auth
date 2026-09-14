package memory_test

import (
	"context"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth/adapters/memory"
	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/plugins/admin"
	"github.com/BladiCreator/go-modular-auth/plugins/jwt"
)

func TestStore_UserAndSessionSorting(t *testing.T) {
	ctx := context.Background()
	store := memory.New()

	u1, err := store.CreateUser(ctx, &dto.CreateUserParams{
		Name:  "Charlie",
		Email: "charlie@example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	time.Sleep(2 * time.Millisecond)

	u2, err := store.CreateUser(ctx, &dto.CreateUserParams{
		Name:  "Alice",
		Email: "alice@example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	time.Sleep(2 * time.Millisecond)

	u3, err := store.CreateUser(ctx, &dto.CreateUserParams{
		Name:  "Bob",
		Email: "bob@example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_ = u2
	_ = u3

	// Test sort by name ASC
	users, total, err := store.ListUsers(ctx, admin.ListUsersFilter{
		SortBy:        "name",
		SortDirection: "asc",
	})
	if err != nil {
		t.Fatalf("ListUsers failed: %v", err)
	}
	if total != 3 {
		t.Fatalf("expected 3 total, got %d", total)
	}
	if users[0].Name != "Alice" || users[1].Name != "Bob" || users[2].Name != "Charlie" {
		t.Errorf("unexpected name asc order: %s, %s, %s", users[0].Name, users[1].Name, users[2].Name)
	}

	// Test sort by email DESC
	usersDesc, _, err := store.ListUsers(ctx, admin.ListUsersFilter{
		SortBy:        "email",
		SortDirection: "desc",
	})
	if err != nil {
		t.Fatalf("ListUsers desc failed: %v", err)
	}
	if usersDesc[0].Email != "charlie@example.com" || usersDesc[2].Email != "alice@example.com" {
		t.Errorf("unexpected email desc order: %s, %s, %s", usersDesc[0].Email, usersDesc[1].Email, usersDesc[2].Email)
	}

	// Test Sessions sorting (descending CreatedAt)
	s1, err := store.CreateSession(ctx, &dto.CreateSessionParams{
		UserID:    u1.ID,
		Token:     "tok1",
		CreatedAt: time.Now().Add(-10 * time.Minute),
		Extra:     map[string]any{"role": "admin"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	s2, err := store.CreateSession(ctx, &dto.CreateSessionParams{
		UserID:    u1.ID,
		Token:     "tok2",
		CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sessions, err := store.ListSessionsByUserID(ctx, u1.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(sessions))
	}
	if sessions[0].ID != s2.ID || sessions[1].ID != s1.ID {
		t.Errorf("expected newest session first: got %s then %s", sessions[0].ID, sessions[1].ID)
	}

	// Test JWK Records sorting (descending CreatedAt)
	k1 := &jwt.JWKRecord{
		ID:        "k1",
		CreatedAt: time.Now().Add(-5 * time.Minute),
	}
	k2 := &jwt.JWKRecord{
		ID:        "k2",
		CreatedAt: time.Now(),
	}
	_ = store.CreateKey(ctx, k1)
	_ = store.CreateKey(ctx, k2)

	keys, err := store.GetAllKeys(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 2 || keys[0].ID != "k2" {
		t.Errorf("expected k2 first in keys, got %v", keys)
	}

	// Test Passkey sorting (ascending CreatedAt)
	pk1 := &entity.Passkey{
		ID:           "pk1",
		CredentialID: "cred1",
		UserID:       u1.ID,
		CreatedAt:    time.Now().Add(-1 * time.Hour),
	}
	pk2 := &entity.Passkey{
		ID:           "pk2",
		CredentialID: "cred2",
		UserID:       u1.ID,
		CreatedAt:    time.Now(),
	}
	if err := store.CreatePasskey(ctx, pk1); err != nil {
		t.Fatalf("CreatePasskey pk1 failed: %v", err)
	}
	if err := store.CreatePasskey(ctx, pk2); err != nil {
		t.Fatalf("CreatePasskey pk2 failed: %v", err)
	}

	passkeys, err := store.ListPasskeysByUserID(ctx, u1.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(passkeys) != 2 || passkeys[0].ID != "pk1" {
		t.Errorf("expected pk1 first in passkeys, got %v", passkeys)
	}
}
