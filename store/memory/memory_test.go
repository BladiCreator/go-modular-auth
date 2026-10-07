package memory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth/store"
	"github.com/BladiCreator/go-modular-auth/store/memory"
	"github.com/BladiCreator/go-modular-auth/user"
	"github.com/BladiCreator/go-modular-auth/verification"
)

func TestTransactionRollback(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	boom := errors.New("boom")
	err := s.Transaction(ctx, func(ctx context.Context) error {
		if err := s.Users().Create(ctx, &user.User{ID: "1", Email: "a@b.co"}); err != nil {
			return err
		}
		// Nested transactions join the outer one.
		return s.Transaction(ctx, func(ctx context.Context) error { return boom })
	})
	if !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
	if _, err := s.Users().GetByID(ctx, "1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("write must be rolled back, got %v", err)
	}
}

func TestUniqueEmail(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	_ = s.Users().Create(ctx, &user.User{ID: "1", Email: "a@b.co"})
	if err := s.Users().Create(ctx, &user.User{ID: "2", Email: "a@b.co"}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("got %v", err)
	}
}

func TestReturnedValuesAreCopies(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	_ = s.Users().Create(ctx, &user.User{ID: "1", Email: "a@b.co"})
	u, _ := s.Users().GetByID(ctx, "1")
	u.EmailVerified = true
	again, _ := s.Users().GetByID(ctx, "1")
	if again.EmailVerified {
		t.Fatal("mutating a returned value must not affect the store")
	}
}

func TestTokenMarkUsedIsSingleUse(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	tok := &verification.Token{ID: "t", TokenHash: "h", Purpose: "p", Subject: "s", ExpiresAt: time.Now().Add(time.Hour)}
	_ = s.Tokens().Create(ctx, tok)
	if err := s.Tokens().MarkUsed(ctx, "t", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.Tokens().MarkUsed(ctx, "t", time.Now()); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("got %v", err)
	}
}
