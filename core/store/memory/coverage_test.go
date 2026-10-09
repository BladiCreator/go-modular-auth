package memory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth/account"
	"github.com/BladiCreator/go-modular-auth/credential"
	"github.com/BladiCreator/go-modular-auth/session"
	"github.com/BladiCreator/go-modular-auth/store"
	"github.com/BladiCreator/go-modular-auth/store/memory"
	"github.com/BladiCreator/go-modular-auth/user"
	"github.com/BladiCreator/go-modular-auth/verification"
)

func TestMemoryStore_UsersComplete(t *testing.T) {
	ctx := context.Background()
	s := memory.New()

	u := &user.User{ID: "u1", Email: "u1@example.com"}
	if err := s.Users().Create(ctx, u); err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// GetByEmail
	byEmail, err := s.Users().GetByEmail(ctx, "u1@example.com")
	if err != nil || byEmail.ID != "u1" {
		t.Fatalf("GetByEmail failed: %v", err)
	}

	// GetByEmail not found
	_, err = s.Users().GetByEmail(ctx, "nonexistent@example.com")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	// Update
	u.EmailVerified = true
	if err := s.Users().Update(ctx, u); err != nil {
		t.Fatalf("failed to update user: %v", err)
	}
	updated, _ := s.Users().GetByID(ctx, "u1")
	if !updated.EmailVerified {
		t.Fatal("expected EmailVerified to be true")
	}

	// Update nonexistent
	if err := s.Users().Update(ctx, &user.User{ID: "nonexistent"}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound on updating nonexistent, got %v", err)
	}

	// Delete
	if err := s.Users().Delete(ctx, "u1"); err != nil {
		t.Fatalf("failed to delete user: %v", err)
	}
	if _, err := s.Users().GetByID(ctx, "u1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected user to be deleted, got %v", err)
	}

	// Delete nonexistent
	if err := s.Users().Delete(ctx, "u1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound on deleting nonexistent, got %v", err)
	}
}

func TestMemoryStore_AccountsComplete(t *testing.T) {
	ctx := context.Background()
	s := memory.New()

	acc := &account.Account{
		ID:         "a1",
		UserID:     "u1",
		Provider:   "google",
		ProviderID: "g-123",
	}

	// Create
	if err := s.Accounts().Create(ctx, acc); err != nil {
		t.Fatalf("failed to create account: %v", err)
	}

	// Conflict on (Provider, ProviderID)
	accDup := &account.Account{
		ID:         "a2",
		UserID:     "u2",
		Provider:   "google",
		ProviderID: "g-123",
	}
	if err := s.Accounts().Create(ctx, accDup); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("expected conflict on duplicate (provider, providerID), got %v", err)
	}

	// GetByID
	got, err := s.Accounts().GetByID(ctx, "a1")
	if err != nil || got.ID != "a1" {
		t.Fatalf("GetByID failed: %v", err)
	}
	_, err = s.Accounts().GetByID(ctx, "nonexistent")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	// GetByProvider
	gotProv, err := s.Accounts().GetByProvider(ctx, "google", "g-123")
	if err != nil || gotProv.ID != "a1" {
		t.Fatalf("GetByProvider failed: %v", err)
	}
	_, err = s.Accounts().GetByProvider(ctx, "google", "unknown")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	// ListByUser
	list, err := s.Accounts().ListByUser(ctx, "u1")
	if err != nil || len(list) != 1 {
		t.Fatalf("expected 1 account in ListByUser, got %d", len(list))
	}

	// Delete
	if err := s.Accounts().Delete(ctx, "a1"); err != nil {
		t.Fatalf("failed to delete account: %v", err)
	}
	if err := s.Accounts().Delete(ctx, "a1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound on deleting nonexistent account, got %v", err)
	}
}

func TestMemoryStore_CredentialsComplete(t *testing.T) {
	ctx := context.Background()
	s := memory.New()

	c := &credential.Credential{
		ID:        "c1",
		UserID:    "u1",
		AccountID: "a1",
		Type:      credential.TypePassword,
		Secret:    "hashed_pw",
		CreatedAt: time.Now(),
	}

	// Create
	if err := s.Credentials().Create(ctx, c); err != nil {
		t.Fatalf("failed to create credential: %v", err)
	}

	// GetByID
	got, err := s.Credentials().GetByID(ctx, "c1")
	if err != nil || got.ID != "c1" {
		t.Fatalf("GetByID failed: %v", err)
	}
	_, err = s.Credentials().GetByID(ctx, "unknown")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	// GetActiveByAccount
	active, err := s.Credentials().GetActiveByAccount(ctx, "a1", credential.TypePassword)
	if err != nil || active.ID != "c1" {
		t.Fatalf("GetActiveByAccount failed: %v", err)
	}

	// ListByUser
	list, err := s.Credentials().ListByUser(ctx, "u1")
	if err != nil || len(list) != 1 {
		t.Fatalf("ListByUser failed: %v", err)
	}

	// Update
	c.Secret = "new_hashed_pw"
	if err := s.Credentials().Update(ctx, c); err != nil {
		t.Fatalf("failed to update credential: %v", err)
	}
	if err := s.Credentials().Update(ctx, &credential.Credential{ID: "unknown"}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound on updating nonexistent, got %v", err)
	}

	// Revoke
	now := time.Now()
	if err := s.Credentials().Revoke(ctx, "c1", now); err != nil {
		t.Fatalf("failed to revoke credential: %v", err)
	}
	_, err = s.Credentials().GetActiveByAccount(ctx, "a1", credential.TypePassword)
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected revoked credential to not be active, got %v", err)
	}
	if err := s.Credentials().Revoke(ctx, "unknown", now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound on revoking nonexistent credential, got %v", err)
	}
}

func TestMemoryStore_SessionsComplete(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	now := time.Now()

	sess1 := &session.Session{
		ID:        "s1",
		UserID:    "u1",
		TokenHash: "tok1",
		ExpiresAt: now.Add(1 * time.Hour),
		CreatedAt: now,
	}
	sess2 := &session.Session{
		ID:        "s2",
		UserID:    "u1",
		TokenHash: "tok2",
		ExpiresAt: now.Add(-1 * time.Hour), // already expired
		CreatedAt: now.Add(-2 * time.Hour),
	}

	if err := s.Sessions().Create(ctx, sess1); err != nil {
		t.Fatalf("failed to create session1: %v", err)
	}
	if err := s.Sessions().Create(ctx, sess2); err != nil {
		t.Fatalf("failed to create session2: %v", err)
	}

	// GetByID & GetByTokenHash
	got, err := s.Sessions().GetByID(ctx, "s1")
	if err != nil || got.ID != "s1" {
		t.Fatalf("GetByID failed: %v", err)
	}
	gotTok, err := s.Sessions().GetByTokenHash(ctx, "tok1")
	if err != nil || gotTok.ID != "s1" {
		t.Fatalf("GetByTokenHash failed: %v", err)
	}
	_, err = s.Sessions().GetByTokenHash(ctx, "unknown")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	// ListByUser
	list, err := s.Sessions().ListByUser(ctx, "u1")
	if err != nil || len(list) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(list))
	}

	// Revoke
	if err := s.Sessions().Revoke(ctx, "s1", now); err != nil {
		t.Fatalf("failed to revoke session: %v", err)
	}
	if err := s.Sessions().Revoke(ctx, "unknown", now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	// RevokeByUser
	revoked, err := s.Sessions().RevokeByUser(ctx, "u1", now)
	if err != nil {
		t.Fatalf("RevokeByUser failed: %v", err)
	}
	if len(revoked) == 0 {
		t.Fatal("expected revoked sessions")
	}

	// DeleteExpired
	n, err := s.Sessions().DeleteExpired(ctx, now)
	if err != nil {
		t.Fatalf("DeleteExpired failed: %v", err)
	}
	if n < 1 {
		t.Errorf("expected at least 1 expired session deleted, got %d", n)
	}
}

func TestMemoryStore_TokensComplete(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	now := time.Now()

	tok := &verification.Token{
		ID:        "t1",
		Purpose:   "reset",
		Subject:   "u1",
		TokenHash: "h1",
		ExpiresAt: now.Add(-10 * time.Minute), // expired
		CreatedAt: now.Add(-20 * time.Minute),
	}
	if err := s.Tokens().Create(ctx, tok); err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	got, err := s.Tokens().GetByHash(ctx, "h1")
	if err != nil || got.ID != "t1" {
		t.Fatalf("GetByHash failed: %v", err)
	}
	_, err = s.Tokens().GetByHash(ctx, "unknown")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound on unknown token hash, got %v", err)
	}

	// DeleteBySubject
	tok2 := &verification.Token{
		ID:        "t2",
		Purpose:   "reset",
		Subject:   "u2",
		TokenHash: "h2",
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
	}
	_ = s.Tokens().Create(ctx, tok2)
	if err := s.Tokens().DeleteBySubject(ctx, "reset", "u2"); err != nil {
		t.Fatalf("DeleteBySubject failed: %v", err)
	}

	// DeleteExpired
	n, err := s.Tokens().DeleteExpired(ctx, now)
	if err != nil {
		t.Fatalf("DeleteExpired failed: %v", err)
	}
	if n != 1 {
		t.Errorf("expected 1 token deleted, got %d", n)
	}
}
