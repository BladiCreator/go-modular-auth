package lastlogin_test

import (
	"context"
	"testing"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapter/memory"
	lastlogin "github.com/BladiCreator/go-modular-auth/plugins/lastlogin"
)

func TestLastLogin_RecordAndGet(t *testing.T) {
	ctx := context.Background()
	mod := lastlogin.New()

	a, err := auth.New(auth.Config{
		Adapter: adaptermem.New(),
		Plugins: []auth.PluginModule{mod},
	})
	if err != nil {
		t.Fatalf("failed to create auth engine: %v", err)
	}

	svc, err := auth.Get[lastlogin.LastLogin](a)
	if err != nil {
		t.Fatalf("failed to get LastLogin service: %v", err)
	}

	// 1. Initial query should return ErrNotFound
	_, err = svc.Get(ctx, "user-1")
	if err != lastlogin.ErrNotFound {
		t.Fatalf("expected ErrNotFound, got: %v", err)
	}

	// 2. Record login
	now := time.Now().UTC().Truncate(time.Second)
	err = svc.Record(ctx, &lastlogin.Record{
		UserID:     "user-1",
		AccountID:  "acc-1",
		Method:     "password",
		IP:         "192.168.1.1",
		UserAgent:  "Mozilla/5.0",
		LoggedInAt: now,
	})
	if err != nil {
		t.Fatalf("failed to record login: %v", err)
	}

	// 3. Query record
	rec, err := svc.Get(ctx, "user-1")
	if err != nil {
		t.Fatalf("expected to get record, got: %v", err)
	}
	if rec.Method != "password" {
		t.Errorf("expected method password, got: %s", rec.Method)
	}
	if rec.IP != "192.168.1.1" {
		t.Errorf("expected IP 192.168.1.1, got: %s", rec.IP)
	}
	if !rec.LoggedInAt.Equal(now) {
		t.Errorf("expected logged in at %v, got %v", now, rec.LoggedInAt)
	}

	// 4. Update login
	err = svc.Record(ctx, &lastlogin.Record{
		UserID:     "user-1",
		Method:     "passkey",
		IP:         "10.0.0.1",
		LoggedInAt: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("failed to update login: %v", err)
	}

	rec2, err := svc.Get(ctx, "user-1")
	if err != nil {
		t.Fatalf("failed to get updated record: %v", err)
	}
	if rec2.Method != "passkey" {
		t.Errorf("expected updated method passkey, got: %s", rec2.Method)
	}
}
