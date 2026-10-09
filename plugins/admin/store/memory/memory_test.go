package memory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth-admin/store"
	"github.com/BladiCreator/go-modular-auth-admin/store/memory"
)

func TestMemoryStore_Lifecycle(t *testing.T) {
	ctx := context.Background()
	s := memory.New()

	rec := &store.UserRecord{
		UserID:    "usr_100",
		Email:     "user100@example.com",
		Disabled:  false,
		IsAdmin:   false,
		Role:      "viewer",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// 1. UpsertUser
	if err := s.UpsertUser(ctx, rec); err != nil {
		t.Fatalf("UpsertUser failed: %v", err)
	}

	// 2. GetUser
	fetched, err := s.GetUser(ctx, "usr_100")
	if err != nil {
		t.Fatalf("GetUser failed: %v", err)
	}
	if fetched.Email != "user100@example.com" || fetched.Disabled {
		t.Fatalf("unexpected fetched user: %+v", fetched)
	}

	// 3. IsUserDisabled & IsAdmin
	dis, err := s.IsUserDisabled(ctx, "usr_100")
	if err != nil || dis {
		t.Fatalf("expected not disabled, got %v, err: %v", dis, err)
	}
	adm, err := s.IsAdmin(ctx, "usr_100")
	if err != nil || adm {
		t.Fatalf("expected not admin, got %v, err: %v", adm, err)
	}

	// 4. UpdateUserStatus
	now := time.Now()
	if err := s.UpdateUserStatus(ctx, "usr_100", true, "abuse", &now); err != nil {
		t.Fatalf("UpdateUserStatus failed: %v", err)
	}
	dis, err = s.IsUserDisabled(ctx, "usr_100")
	if err != nil || !dis {
		t.Fatalf("expected disabled true, got %v, err: %v", dis, err)
	}

	// 5. SetAdminRole
	if err := s.SetAdminRole(ctx, "usr_100", true, "superadmin"); err != nil {
		t.Fatalf("SetAdminRole failed: %v", err)
	}
	adm, err = s.IsAdmin(ctx, "usr_100")
	if err != nil || !adm {
		t.Fatalf("expected admin true, got %v, err: %v", adm, err)
	}

	// 6. ListUsers
	users, total, err := s.ListUsers(ctx, store.ListFilter{Limit: 10})
	if err != nil {
		t.Fatalf("ListUsers failed: %v", err)
	}
	if total != 1 || len(users) != 1 {
		t.Fatalf("expected 1 user, got %d total, %d returned", total, len(users))
	}

	// 7. DeleteUser
	if err := s.DeleteUser(ctx, "usr_100"); err != nil {
		t.Fatalf("DeleteUser failed: %v", err)
	}
	_, err = s.GetUser(ctx, "usr_100")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
}

func TestMemoryStore_TransactionRollback(t *testing.T) {
	ctx := context.Background()
	s := memory.New()

	rec := &store.UserRecord{
		UserID:    "usr_200",
		Email:     "rollback@example.com",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	_ = s.UpsertUser(ctx, rec)

	errAbort := errors.New("aborted")
	err := s.Transaction(ctx, func(txCtx context.Context) error {
		now := time.Now()
		if err := s.UpdateUserStatus(txCtx, "usr_200", true, "bad", &now); err != nil {
			return err
		}
		return errAbort
	})

	if !errors.Is(err, errAbort) {
		t.Fatalf("expected errAbort, got %v", err)
	}

	// Verify rollback
	fetched, err := s.GetUser(ctx, "usr_200")
	if err != nil {
		t.Fatalf("GetUser failed: %v", err)
	}
	if fetched.Disabled {
		t.Fatalf("expected disabled false after rollback, got true")
	}
}
