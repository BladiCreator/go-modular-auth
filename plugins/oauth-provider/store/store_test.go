package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth-oauth-provider/store"
	"github.com/BladiCreator/go-modular-auth-oauth-provider/store/memory"
)

func testStoreContract(t *testing.T, s store.Store) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)

	// --- 1. ClientStore Tests ---
	c := &store.Client{
		ID:                "client_contract_1",
		SecretHash:        "hash_123",
		Name:              "Contract Client",
		ClientType:        store.ClientTypeConfidential,
		RedirectURIs:      []string{"https://example.com/cb"},
		AllowedGrantTypes: []string{"authorization_code"},
		AllowedScopes:     []string{"read", "write"},
		Status:            store.ClientStatusActive,
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	if err := s.Clients().Create(ctx, c); err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	if err := s.Clients().Create(ctx, c); err != store.ErrConflict {
		t.Errorf("expected ErrConflict on duplicate client creation, got %v", err)
	}

	fetched, err := s.Clients().GetByID(ctx, c.ID)
	if err != nil {
		t.Fatalf("failed to get client: %v", err)
	}
	if fetched.Name != c.Name {
		t.Errorf("expected name %s, got %s", c.Name, fetched.Name)
	}

	if err := s.Clients().Revoke(ctx, c.ID, now); err != nil {
		t.Fatalf("failed to revoke client: %v", err)
	}
	fetchedRevoked, err := s.Clients().GetByID(ctx, c.ID)
	if err != nil || fetchedRevoked.Status != store.ClientStatusRevoked {
		t.Errorf("expected client status revoked, got %v", fetchedRevoked)
	}

	// --- 2. CodeStore Tests ---
	code := &store.AuthorizationCode{
		ID:                  "code_contract_1",
		CodeHash:            "code_hash_1",
		ClientID:            c.ID,
		UserID:              "user_1",
		RedirectURI:         "https://example.com/cb",
		Scopes:              []string{"read"},
		CodeChallenge:       "challenge_abc",
		CodeChallengeMethod: "S256",
		ExpiresAt:           now.Add(5 * time.Minute),
		CreatedAt:           now,
	}

	if err := s.Codes().Create(ctx, code); err != nil {
		t.Fatalf("failed to create code: %v", err)
	}
	if err := s.Codes().Create(ctx, code); err != store.ErrConflict {
		t.Errorf("expected ErrConflict on duplicate code, got %v", err)
	}

	consumed, err := s.Codes().Consume(ctx, code.CodeHash, now)
	if err != nil {
		t.Fatalf("failed to consume code: %v", err)
	}
	if consumed.ConsumedAt == nil {
		t.Errorf("expected ConsumedAt to be populated")
	}

	// Second consume must fail
	_, err = s.Codes().Consume(ctx, code.CodeHash, now)
	if err != store.ErrConflict {
		t.Errorf("expected ErrConflict on already-consumed code, got %v", err)
	}

	// --- 3. TokenStore Tests ---
	acc := &store.AccessToken{
		ID:        "acc_contract_1",
		TokenHash: "acc_hash_1",
		ClientID:  c.ID,
		UserID:    "user_1",
		Scopes:    []string{"read"},
		ExpiresAt: now.Add(1 * time.Hour),
		CreatedAt: now,
	}

	if err := s.Tokens().CreateAccessToken(ctx, acc); err != nil {
		t.Fatalf("failed to create access token: %v", err)
	}
	fetchedAcc, err := s.Tokens().GetAccessTokenByHash(ctx, acc.TokenHash)
	if err != nil || fetchedAcc.ID != acc.ID {
		t.Errorf("failed to get access token: %v", err)
	}

	if err := s.Tokens().RevokeAccessToken(ctx, acc.TokenHash, now); err != nil {
		t.Fatalf("failed to revoke access token: %v", err)
	}
	fetchedRevokedAcc, err := s.Tokens().GetAccessTokenByHash(ctx, acc.TokenHash)
	if err != nil || fetchedRevokedAcc.RevokedAt == nil {
		t.Errorf("expected access token to have RevokedAt")
	}

	// --- 4. Transaction Tests ---
	err = s.Transaction(ctx, func(txCtx context.Context) error {
		return nil
	})
	if err != nil {
		t.Errorf("expected transaction to succeed, got %v", err)
	}
}

func TestMemoryStoreContract(t *testing.T) {
	s := memory.New()
	testStoreContract(t, s)
}
