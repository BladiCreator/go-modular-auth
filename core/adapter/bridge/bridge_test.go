package bridge_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth/account"
	"github.com/BladiCreator/go-modular-auth/adapter/bridge"
	"github.com/BladiCreator/go-modular-auth/adapter/memory"
	"github.com/BladiCreator/go-modular-auth/credential"
	"github.com/BladiCreator/go-modular-auth/schema"
	"github.com/BladiCreator/go-modular-auth/session"
	"github.com/BladiCreator/go-modular-auth/store"
	"github.com/BladiCreator/go-modular-auth/user"
	"github.com/BladiCreator/go-modular-auth/verification"
)

func setupBridge(t *testing.T) store.Store {
	s, err := schema.DefaultCoreSchema()
	if err != nil {
		t.Fatalf("DefaultCoreSchema() error = %v", err)
	}
	mem := memory.New()
	if err := mem.RegisterSchema(context.Background(), s); err != nil {
		t.Fatalf("RegisterSchema error = %v", err)
	}
	return bridge.New(mem)
}

func TestBridge_Users(t *testing.T) {
	ctx := context.Background()
	st := setupBridge(t)

	now := time.Now().UTC()
	u := &user.User{
		ID:            "u1",
		Email:         "bob@example.com",
		EmailVerified: false,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	if err := st.Users().Create(ctx, u); err != nil {
		t.Fatalf("Users().Create failed: %v", err)
	}

	// Duplicate email must return store.ErrConflict
	u2 := &user.User{
		ID:        "u2",
		Email:     "bob@example.com",
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := st.Users().Create(ctx, u2); !errors.Is(err, store.ErrConflict) {
		t.Errorf("expected store.ErrConflict on duplicate email, got: %v", err)
	}

	// GetByID
	got, err := st.Users().GetByID(ctx, "u1")
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}
	if got.Email != "bob@example.com" {
		t.Errorf("got email %v, expected bob@example.com", got.Email)
	}

	// GetByEmail
	gotByEmail, err := st.Users().GetByEmail(ctx, "bob@example.com")
	if err != nil {
		t.Fatalf("GetByEmail failed: %v", err)
	}
	if gotByEmail.ID != "u1" {
		t.Errorf("got ID %v, expected u1", gotByEmail.ID)
	}
}

func TestBridge_Sessions(t *testing.T) {
	ctx := context.Background()
	st := setupBridge(t)

	now := time.Now().UTC()
	s := &session.Session{
		ID:        "sess1",
		UserID:    "u1",
		TokenHash: "hash123",
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
	}

	if err := st.Sessions().Create(ctx, s); err != nil {
		t.Fatalf("Sessions().Create failed: %v", err)
	}

	got, err := st.Sessions().GetByTokenHash(ctx, "hash123")
	if err != nil {
		t.Fatalf("GetByTokenHash failed: %v", err)
	}
	if got.ID != "sess1" {
		t.Errorf("expected sess1, got %v", got.ID)
	}

	if err := st.Sessions().Revoke(ctx, "sess1", now); err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}

	gotRevoked, err := st.Sessions().GetByID(ctx, "sess1")
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}
	if gotRevoked.RevokedAt == nil {
		t.Errorf("expected session to be revoked")
	}
}

func TestBridge_Tokens(t *testing.T) {
	ctx := context.Background()
	st := setupBridge(t)

	now := time.Now().UTC()
	tok := &verification.Token{
		ID:        "tok1",
		Purpose:   verification.PurposeEmailVerification,
		Subject:   "u1",
		TokenHash: "tokenhash1",
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
	}

	if err := st.Tokens().Create(ctx, tok); err != nil {
		t.Fatalf("Tokens().Create failed: %v", err)
	}

	// Single-use guarantee
	if err := st.Tokens().MarkUsed(ctx, "tok1", now); err != nil {
		t.Fatalf("MarkUsed failed: %v", err)
	}
	// Second MarkUsed must return ErrConflict
	if err := st.Tokens().MarkUsed(ctx, "tok1", now); !errors.Is(err, store.ErrConflict) {
		t.Errorf("expected ErrConflict on already used token, got: %v", err)
	}
}

func TestBridge_AccountsAndCredentials(t *testing.T) {
	ctx := context.Background()
	st := setupBridge(t)

	now := time.Now().UTC()
	acc := &account.Account{
		ID:         "acc1",
		UserID:     "u1",
		Provider:   account.ProviderPassword,
		ProviderID: "u1",
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if err := st.Accounts().Create(ctx, acc); err != nil {
		t.Fatalf("Accounts.Create failed: %v", err)
	}

	cred := &credential.Credential{
		ID:        "cred1",
		UserID:    "u1",
		AccountID: "acc1",
		Type:      credential.TypePassword,
		Secret:    "hashedsecret",
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := st.Credentials().Create(ctx, cred); err != nil {
		t.Fatalf("Credentials.Create failed: %v", err)
	}

	active, err := st.Credentials().GetActiveByAccount(ctx, "acc1", credential.TypePassword)
	if err != nil {
		t.Fatalf("GetActiveByAccount failed: %v", err)
	}
	if active.Secret != "hashedsecret" {
		t.Errorf("expected hashedsecret, got %v", active.Secret)
	}
}
