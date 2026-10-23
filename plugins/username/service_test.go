package username_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	auth "github.com/BladiCreator/go-modular-auth"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapter/memory"
	memcache "github.com/BladiCreator/go-modular-auth/cache/memory"
	"github.com/BladiCreator/go-modular-auth/password"
	"github.com/BladiCreator/go-modular-auth/plugins/username"
)

var fastHasher = password.NewArgon2id(password.Argon2idParams{Memory: 64, Iterations: 1})

func setupTestAuth(t *testing.T, opts ...username.Option) (*auth.Auth, username.Capability) {
	t.Helper()

	uMod := username.New(opts...)
	a, err := auth.New(auth.Config{
		Adapter: adaptermem.New(),
		Cache:   memcache.New(),
		Hasher:  fastHasher,
		Plugins: []auth.PluginModule{uMod},
	})
	if err != nil {
		t.Fatalf("failed to initialize auth: %v", err)
	}

	cap, err := auth.Get[username.Capability](a)
	if err != nil {
		t.Fatalf("failed to retrieve username capability: %v", err)
	}

	return a, cap
}

func TestRegistrationAndAuthentication(t *testing.T) {
	ctx := context.Background()
	_, cap := setupTestAuth(t)

	// 1. Register new user with username
	res, err := cap.Register(ctx, username.RegisterInput{
		Email:    "alice@example.com",
		Username: "AliceSmith",
		Password: "SecurePassword123!",
	})
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	if res.User == nil || res.Session == nil || res.Token == "" {
		t.Fatal("expected user, session and token to be populated")
	}

	// 2. Lookup & Get
	rec, err := cap.GetByUsername(ctx, "alicesmith")
	if err != nil {
		t.Fatalf("GetByUsername failed: %v", err)
	}
	if rec.UserID != res.User.ID || rec.Username != "AliceSmith" || rec.Normalized != "alicesmith" {
		t.Fatalf("unexpected record: %+v", rec)
	}

	userID, err := cap.Lookup(ctx, "ALICESMITH")
	if err != nil {
		t.Fatalf("Lookup with uppercase failed: %v", err)
	}
	if userID != res.User.ID {
		t.Fatalf("expected userID %s, got %s", res.User.ID, userID)
	}

	// 3. Authenticate with exact username
	authRes, err := cap.Authenticate(ctx, username.AuthenticateInput{
		Username: "AliceSmith",
		Password: "SecurePassword123!",
	})
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}
	if authRes.User.ID != res.User.ID || authRes.Token == "" {
		t.Fatal("unexpected auth result")
	}

	// 4. Authenticate with lowercase username
	authRes2, err := cap.Authenticate(ctx, username.AuthenticateInput{
		Username: "alicesmith",
		Password: "SecurePassword123!",
	})
	if err != nil {
		t.Fatalf("Authenticate with lowercase failed: %v", err)
	}
	if authRes2.User.ID != res.User.ID {
		t.Fatal("mismatched user ID")
	}

	// 5. Authenticate with wrong password -> ErrInvalidCredentials
	_, err = cap.Authenticate(ctx, username.AuthenticateInput{
		Username: "alicesmith",
		Password: "WrongPassword!",
	})
	if !errors.Is(err, username.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials for wrong password, got %v", err)
	}

	// 6. Authenticate with non-existent username -> ErrInvalidCredentials
	_, err = cap.Authenticate(ctx, username.AuthenticateInput{
		Username: "nonexistent",
		Password: "SecurePassword123!",
	})
	if !errors.Is(err, username.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials for missing user, got %v", err)
	}

	// 7. Duplicate registration rejected
	_, err = cap.Register(ctx, username.RegisterInput{
		Email:    "other@example.com",
		Username: "alicesmith", // same normalized
		Password: "SecurePassword123!",
	})
	if !errors.Is(err, username.ErrTaken) {
		t.Fatalf("expected ErrTaken on duplicate registration, got %v", err)
	}
}

func TestSetAndChangeUsername(t *testing.T) {
	ctx := context.Background()
	a, cap := setupTestAuth(t)

	// Create user directly via Core SignUp
	coreRes, err := a.SignUp(ctx, auth.SignUpInput{
		Email:    "bob@example.com",
		Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("Core SignUp failed: %v", err)
	}

	// Set username for existing user
	if err := cap.Set(ctx, coreRes.User.ID, "BobBuilder"); err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	// Double set should fail
	if err := cap.Set(ctx, coreRes.User.ID, "BobAgain"); !errors.Is(err, username.ErrAlreadyAssigned) {
		t.Fatalf("expected ErrAlreadyAssigned, got %v", err)
	}

	// Verify Bob can authenticate with username
	authRes, err := cap.Authenticate(ctx, username.AuthenticateInput{
		Username: "bobbuilder",
		Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("Authenticate after Set failed: %v", err)
	}
	if authRes.User.ID != coreRes.User.ID {
		t.Fatal("user ID mismatch")
	}

	// Change username
	if err := cap.Change(ctx, coreRes.User.ID, "BobTheBuilder"); err != nil {
		t.Fatalf("Change failed: %v", err)
	}

	// Old username should now fail to authenticate
	_, err = cap.Authenticate(ctx, username.AuthenticateInput{
		Username: "bobbuilder",
		Password: "Password123!",
	})
	if !errors.Is(err, username.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials for old username, got %v", err)
	}

	// New username succeeds
	_, err = cap.Authenticate(ctx, username.AuthenticateInput{
		Username: "bobthebuilder",
		Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("Authenticate with new username failed: %v", err)
	}

	// Delete username
	if err := cap.Delete(ctx, coreRes.User.ID); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	if _, err := cap.GetByUserID(ctx, coreRes.User.ID); !errors.Is(err, username.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after deletion, got %v", err)
	}
}

func TestConcurrentRegistrationRace(t *testing.T) {
	ctx := context.Background()
	_, cap := setupTestAuth(t)

	const concurrency = 10
	var wg sync.WaitGroup
	wg.Add(concurrency)

	successCount := 0
	conflictCount := 0
	var mu sync.Mutex

	for i := 0; i < concurrency; i++ {
		go func(id int) {
			defer wg.Done()
			_, err := cap.Register(ctx, username.RegisterInput{
				Email:    "test" + string(rune('a'+id)) + "@example.com",
				Username: "RaceWinner",
				Password: "Password123!",
			})

			mu.Lock()
			if err == nil {
				successCount++
			} else if errors.Is(err, username.ErrTaken) {
				conflictCount++
			}
			mu.Unlock()
		}(i)
	}

	wg.Wait()

	if successCount != 1 {
		t.Fatalf("expected exactly 1 successful registration, got %d", successCount)
	}
	if conflictCount != concurrency-1 {
		t.Fatalf("expected %d conflicts, got %d", concurrency-1, conflictCount)
	}
}

func TestPluginEvents(t *testing.T) {
	ctx := context.Background()
	var eventsReceived []auth.EventName
	var mu sync.Mutex

	uMod := username.New()
	a, err := auth.New(auth.Config{
		Adapter: adaptermem.New(),
		Hasher:  fastHasher,
		Plugins: []auth.PluginModule{uMod},
	})
	if err != nil {
		t.Fatal(err)
	}

	a.Events().SubscribeAll(func(ctx context.Context, e auth.Event) {
		mu.Lock()
		eventsReceived = append(eventsReceived, e.Name)
		mu.Unlock()
	})

	cap, err := auth.Get[username.Capability](a)
	if err != nil {
		t.Fatal(err)
	}

	res, err := cap.Register(ctx, username.RegisterInput{
		Email:    "ev@test.com",
		Username: "EventUser",
		Password: "Password123!",
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := cap.Change(ctx, res.User.ID, "EventUser2"); err != nil {
		t.Fatal(err)
	}

	if err := cap.Delete(ctx, res.User.ID); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()

	hasCreated := false
	hasUpdated := false
	hasDeleted := false
	for _, ev := range eventsReceived {
		if ev == username.EventCreated {
			hasCreated = true
		}
		if ev == username.EventUpdated {
			hasUpdated = true
		}
		if ev == username.EventDeleted {
			hasDeleted = true
		}
	}

	if !hasCreated || !hasUpdated || !hasDeleted {
		t.Fatalf("missing expected events, received: %v", eventsReceived)
	}
}
