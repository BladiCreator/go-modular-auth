package memory_test

import (
	"context"
	"testing"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth/adapters/memory"
	"github.com/BladiCreator/go-modular-auth/email"
)

func TestMemoryAdaptersIntegration(t *testing.T) {
	ad := memory.NewAdapter()
	c := memory.NewCache()
	e := memory.NewEmail()

	engine, err := auth.New(auth.Config{
		Adapter: ad,
		Cache:   c,
		Email:   e,
	})
	if err != nil {
		t.Fatalf("auth.New failed: %v", err)
	}

	ctx := context.Background()

	// 1. SignUp
	signUpRes, err := engine.SignUp(ctx, auth.SignUpInput{
		Email:    "test@example.com",
		Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("SignUp failed: %v", err)
	}
	if signUpRes.User == nil || signUpRes.User.ID == "" {
		t.Fatal("expected valid user from SignUp")
	}

	// 2. SignIn
	signInRes, err := engine.SignIn(ctx, auth.SignInInput{
		Email:    "test@example.com",
		Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("SignIn failed: %v", err)
	}
	if signInRes.Token == "" {
		t.Fatal("expected non-empty session token")
	}

	// 3. GetSession
	sessRes, err := engine.GetSession(ctx, signInRes.Token)
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	if sessRes.User.ID != signUpRes.User.ID {
		t.Fatalf("expected user ID %s, got %s", signUpRes.User.ID, sessRes.User.ID)
	}

	// 4. Test Cache adapter
	if err := c.Set(ctx, "test-key", "test-val", 5*time.Minute); err != nil {
		t.Fatalf("cache.Set failed: %v", err)
	}
	var cachedVal string
	if err := c.Get(ctx, "test-key", &cachedVal); err != nil || cachedVal != "test-val" {
		t.Fatalf("cache.Get failed or mismatched: %v, val: %s", err, cachedVal)
	}

	// 5. Test Email adapter
	if err := e.Send(ctx, email.Message{
		To:      "recipient@example.com",
		Subject: "Hello",
		Text:    "Test message",
	}); err != nil {
		t.Fatalf("email.Send failed: %v", err)
	}
}
