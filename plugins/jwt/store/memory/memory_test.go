package memory

import (
	"context"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth-jwt/store"
)

func TestMemoryStore_TokenRevocation(t *testing.T) {
	s := New()
	ctx := context.Background()
	now := time.Now()

	// 1. Check non-existent token
	revoked, err := s.IsTokenRevoked(ctx, "jti-1")
	if err != nil || revoked {
		t.Fatalf("expected not revoked, got %v, err: %v", revoked, err)
	}

	// 2. Revoke token
	rec := &store.RevocationRecord{
		JTI:       "jti-1",
		Subject:   "user-1",
		Reason:    "logout",
		ExpiresAt: now.Add(10 * time.Minute),
		RevokedAt: now,
	}
	if err := s.RevokeToken(ctx, rec); err != nil {
		t.Fatalf("RevokeToken failed: %v", err)
	}

	// 3. Check revoked token
	revoked, err = s.IsTokenRevoked(ctx, "jti-1")
	if err != nil || !revoked {
		t.Fatalf("expected revoked, got %v, err: %v", revoked, err)
	}

	// 4. DeleteExpired
	deleted, err := s.DeleteExpired(ctx, now.Add(15*time.Minute))
	if err != nil || deleted != 1 {
		t.Fatalf("expected 1 deleted, got %d, err: %v", deleted, err)
	}

	revoked, _ = s.IsTokenRevoked(ctx, "jti-1")
	if revoked {
		t.Fatal("expected expired token to no longer be present")
	}
}

func TestMemoryStore_SubjectRevocation(t *testing.T) {
	s := New()
	ctx := context.Background()
	now := time.Now()

	// Subject cutoff revocation
	cutoff := now.Add(-5 * time.Minute)
	rec := &store.SubjectRevocationRecord{
		Subject:   "user-99",
		Cutoff:    cutoff,
		Reason:    "password_reset",
		RevokedAt: now,
	}
	if err := s.RevokeSubject(ctx, rec); err != nil {
		t.Fatalf("RevokeSubject failed: %v", err)
	}

	// Token issued BEFORE cutoff -> revoked
	revoked, err := s.IsSubjectRevoked(ctx, "user-99", cutoff.Add(-1*time.Minute))
	if err != nil || !revoked {
		t.Fatalf("expected token before cutoff to be revoked, got %v", revoked)
	}

	// Token issued AFTER cutoff -> active
	revoked, err = s.IsSubjectRevoked(ctx, "user-99", cutoff.Add(1*time.Minute))
	if err != nil || revoked {
		t.Fatalf("expected token after cutoff to NOT be revoked, got %v", revoked)
	}
}
