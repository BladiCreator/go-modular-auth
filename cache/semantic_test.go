package cache_test

import (
	"context"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth/cache"
	cachememory "github.com/BladiCreator/go-modular-auth/cache/memory"
	"github.com/BladiCreator/go-modular-auth/session"
	"github.com/BladiCreator/go-modular-auth/user"
)

func TestSemanticCache_Session(t *testing.T) {
	ctx := context.Background()
	c := cachememory.New()
	sc := cache.NewSessionCache(c)

	sess := &session.Session{
		ID:        "s-1",
		UserID:    "u-1",
		TokenHash: "hash-xyz",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		CreatedAt: time.Now(),
	}

	// 1. Get non-existent
	_, err := sc.Get(ctx, "hash-xyz")
	if err == nil {
		t.Fatal("expected error getting non-existent session from cache")
	}

	// 2. Set
	if err := sc.Set(ctx, sess, 1*time.Hour); err != nil {
		t.Fatalf("failed to set session in cache: %v", err)
	}

	// 3. Get existing
	got, err := sc.Get(ctx, "hash-xyz")
	if err != nil {
		t.Fatalf("failed to get session from cache: %v", err)
	}
	if got.ID != sess.ID || got.UserID != sess.UserID {
		t.Errorf("mismatched session from cache: %+v", got)
	}

	// 4. Delete
	if err := sc.Delete(ctx, "hash-xyz"); err != nil {
		t.Fatalf("failed to delete session from cache: %v", err)
	}
	_, err = sc.Get(ctx, "hash-xyz")
	if err == nil {
		t.Fatal("expected error getting deleted session from cache")
	}
}

func TestSemanticCache_User(t *testing.T) {
	ctx := context.Background()
	c := cachememory.New()
	uc := cache.NewUserCache(c)

	u := &user.User{
		ID:            "u-1",
		Email:         "user@example.com",
		EmailVerified: true,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	// 1. Get non-existent
	_, err := uc.Get(ctx, "u-1")
	if err == nil {
		t.Fatal("expected error getting non-existent user from cache")
	}

	// 2. Set
	if err := uc.Set(ctx, u, 1*time.Hour); err != nil {
		t.Fatalf("failed to set user in cache: %v", err)
	}

	// 3. Get existing
	got, err := uc.Get(ctx, "u-1")
	if err != nil {
		t.Fatalf("failed to get user from cache: %v", err)
	}
	if got.ID != u.ID || got.Email != u.Email {
		t.Errorf("mismatched user from cache: %+v", got)
	}

	// 4. Delete
	if err := uc.Delete(ctx, "u-1"); err != nil {
		t.Fatalf("failed to delete user from cache: %v", err)
	}
	_, err = uc.Get(ctx, "u-1")
	if err == nil {
		t.Fatal("expected error getting deleted user from cache")
	}
}
