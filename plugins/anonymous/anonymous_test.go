package anonymous_test

import (
	"context"
	"errors"
	"testing"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapter/memory"
	corecache "github.com/BladiCreator/go-modular-auth/cache/memory"
	"github.com/BladiCreator/go-modular-auth/plugins/anonymous"
	"github.com/BladiCreator/go-modular-auth/plugins/anonymous/plugins"
)

type testHarness struct {
	auth   *auth.Auth
	anon   anonymous.Anonymous
	events []auth.Event
}

func setupHarness(t *testing.T, opts ...anonymous.Option) *testHarness {
	t.Helper()
	ad := adaptermem.New()
	cacheAdapter := corecache.New()

	h := &testHarness{}

	anonPlugin := anonymous.New(opts...)

	engine, err := auth.New(auth.Config{
		Adapter: ad,
		Cache:   cacheAdapter,
		Plugins: []auth.PluginModule{
			anonPlugin,
		},
	})
	if err != nil {
		t.Fatalf("failed to initialize auth engine: %v", err)
	}

	engine.Events().SubscribeAll(func(ctx context.Context, e auth.Event) {
		h.events = append(h.events, e)
	})

	anonCap, err := auth.Get[plugins.Anonymous](engine)
	if err != nil {
		t.Fatalf("failed to retrieve Anonymous capability: %v", err)
	}

	h.auth = engine
	h.anon = anonCap
	return h
}

func TestAnonymous_CreateAndSession(t *testing.T) {
	ctx := context.Background()
	h := setupHarness(t)

	res, err := h.anon.Authenticate(ctx, anonymous.AuthenticateInput{
		Session: auth.SessionOptions{
			IPAddress: "127.0.0.1",
			UserAgent: "TestBrowser/1.0",
		},
		Metadata: map[string]string{
			"source": "landing_page",
		},
	})
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}

	if res.User == nil || res.User.ID == "" {
		t.Fatal("expected User with ID")
	}
	if res.Session == nil || res.Session.ID == "" {
		t.Fatal("expected Session with ID")
	}
	if res.Token == "" {
		t.Fatal("expected plaintext session token")
	}
	if res.Identity == nil || res.Identity.ID == "" {
		t.Fatal("expected Identity with ID")
	}

	// Verify session is valid via Core auth
	sessResult, err := h.auth.GetSession(ctx, res.Token)
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	if sessResult == nil || sessResult.User.ID != res.User.ID {
		t.Fatalf("expected session to resolve user %s", res.User.ID)
	}

	// Verify Identity retrieval
	ident, err := h.anon.GetIdentity(ctx, res.User.ID)
	if err != nil {
		t.Fatalf("GetIdentity failed: %v", err)
	}
	if ident.ID != res.Identity.ID || ident.Metadata["source"] != "landing_page" {
		t.Fatalf("unexpected identity: %+v", ident)
	}

	// Verify IsAnonymous
	isAnon, err := h.anon.IsAnonymous(ctx, res.User.ID)
	if err != nil || !isAnon {
		t.Fatalf("expected IsAnonymous=true, got %v (err: %v)", isAnon, err)
	}

	// Verify Principal check
	p, err := h.anon.Principal(ctx, res.User.ID)
	if err != nil {
		t.Fatalf("Principal failed: %v", err)
	}
	if p.Type != anonymous.PrincipalAnonymous {
		t.Fatalf("expected Principal type %q, got %q", anonymous.PrincipalAnonymous, p.Type)
	}
}

func TestAnonymous_ConvertInPlace(t *testing.T) {
	ctx := context.Background()
	h := setupHarness(t)

	authRes, err := h.anon.Authenticate(ctx, anonymous.AuthenticateInput{})
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}
	anonUserID := authRes.User.ID

	// Attempt conversion with invalid email
	_, err = h.anon.Convert(ctx, anonymous.ConvertInput{
		AnonymousUserID: anonUserID,
		Email:           "not-an-email",
		Password:        "Password123!",
	})
	if !errors.Is(err, anonymous.ErrInvalidEmail) {
		t.Fatalf("expected ErrInvalidEmail, got %v", err)
	}

	// Attempt conversion with short password
	_, err = h.anon.Convert(ctx, anonymous.ConvertInput{
		AnonymousUserID: anonUserID,
		Email:           "valid@example.com",
		Password:        "123",
	})
	if !errors.Is(err, anonymous.ErrInvalidPassword) {
		t.Fatalf("expected ErrInvalidPassword, got %v", err)
	}

	// Perform successful conversion
	convRes, err := h.anon.Convert(ctx, anonymous.ConvertInput{
		AnonymousUserID: anonUserID,
		AnonymousToken:  authRes.Token,
		Email:           "newuser@example.com",
		Password:        "ValidPassword123!",
	})
	if err != nil {
		t.Fatalf("Convert failed: %v", err)
	}

	if convRes.User.Email != "newuser@example.com" {
		t.Fatalf("expected updated email, got %s", convRes.User.Email)
	}
	if !convRes.Identity.Converted() {
		t.Fatal("expected Identity.Converted() to be true")
	}

	// User should no longer be anonymous
	isAnon, err := h.anon.IsAnonymous(ctx, anonUserID)
	if err != nil || isAnon {
		t.Fatalf("expected IsAnonymous=false after conversion, got %v", isAnon)
	}

	// Principal should now be standard user
	p, err := h.anon.Principal(ctx, anonUserID)
	if err != nil || p.Type != auth.PrincipalUser {
		t.Fatalf("expected Principal type 'user', got %v", p.Type)
	}

	// Core Sign-in with the converted permanent credentials should work!
	signInRes, err := h.auth.SignIn(ctx, auth.SignInInput{
		Email:    "newuser@example.com",
		Password: "ValidPassword123!",
	})
	if err != nil {
		t.Fatalf("core SignIn failed for converted user: %v", err)
	}
	if signInRes.User.ID != anonUserID {
		t.Fatalf("expected signed-in user ID %s, got %s", anonUserID, signInRes.User.ID)
	}

	// Attempting to convert again must fail
	_, err = h.anon.Convert(ctx, anonymous.ConvertInput{
		AnonymousUserID: anonUserID,
		Email:           "another@example.com",
		Password:        "AnotherPassword123!",
	})
	if !errors.Is(err, anonymous.ErrAlreadyConverted) {
		t.Fatalf("expected ErrAlreadyConverted, got %v", err)
	}
}

func TestAnonymous_ConvertWithAccount(t *testing.T) {
	ctx := context.Background()
	h := setupHarness(t)

	authRes, err := h.anon.Authenticate(ctx, anonymous.AuthenticateInput{})
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}

	convRes, err := h.anon.ConvertWithAccount(ctx, anonymous.ConvertAccountInput{
		AnonymousUserID: authRes.User.ID,
		Provider:        "oauth:github",
		ProviderID:      "gh-123456",
		Email:           "dev@github.com",
	})
	if err != nil {
		t.Fatalf("ConvertWithAccount failed: %v", err)
	}

	if convRes.User.Email != "dev@github.com" {
		t.Fatalf("expected email updated, got %s", convRes.User.Email)
	}
	if !convRes.Identity.Converted() {
		t.Fatal("expected Converted() to be true")
	}

	// Verify Account was saved in Core store
	acc, err := h.auth.Store().Accounts().GetByProvider(ctx, "oauth:github", "gh-123456")
	if err != nil {
		t.Fatalf("core Account not found: %v", err)
	}
	if acc.UserID != authRes.User.ID {
		t.Fatalf("expected account user %s, got %s", authRes.User.ID, acc.UserID)
	}
}

func TestAnonymous_LinkToPermanent(t *testing.T) {
	ctx := context.Background()
	h := setupHarness(t)

	// 1. Create a permanent user via Core SignUp
	permSignUp, err := h.auth.SignUp(ctx, auth.SignUpInput{
		Email:    "permanent@example.com",
		Password: "PermanentPassword123!",
	})
	if err != nil {
		t.Fatalf("core SignUp failed: %v", err)
	}
	permUserID := permSignUp.User.ID

	// 2. Create an anonymous user
	anonRes, err := h.anon.Authenticate(ctx, anonymous.AuthenticateInput{})
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}
	anonUserID := anonRes.User.ID

	// 3. Attempt to link with invalid password
	_, err = h.anon.Link(ctx, anonymous.LinkInput{
		AnonymousUserID:   anonUserID,
		PermanentEmail:    "permanent@example.com",
		PermanentPassword: "WrongPassword!",
	})
	if !errors.Is(err, anonymous.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}

	// 4. Attempt to link to self
	_, err = h.anon.Link(ctx, anonymous.LinkInput{
		AnonymousUserID: anonUserID,
		PermanentToken:  anonRes.Token,
	})
	if !errors.Is(err, anonymous.ErrSameAccount) {
		t.Fatalf("expected ErrSameAccount, got %v", err)
	}

	// 5. Successful link using password credentials
	linkRes, err := h.anon.Link(ctx, anonymous.LinkInput{
		AnonymousUserID:         anonUserID,
		PermanentEmail:          "permanent@example.com",
		PermanentPassword:       "PermanentPassword123!",
		RevokeAnonymousSessions: true,
	})
	if err != nil {
		t.Fatalf("Link failed: %v", err)
	}

	if linkRes.PermanentUser.ID != permUserID {
		t.Fatalf("expected permanent user ID %s, got %s", permUserID, linkRes.PermanentUser.ID)
	}
	if linkRes.Identity.LinkedUserID != permUserID {
		t.Fatalf("expected LinkedUserID %s, got %s", permUserID, linkRes.Identity.LinkedUserID)
	}

	// Anonymous session should have been revoked
	sessRes, err := h.auth.GetSession(ctx, anonRes.Token)
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	if sessRes != nil {
		t.Fatal("expected anonymous session to be revoked after link")
	}

	// Attempting to link another anonymous user to this anonymous identity must fail
	anotherAnon, _ := h.anon.Authenticate(ctx, anonymous.AuthenticateInput{})
	_, err = h.anon.Link(ctx, anonymous.LinkInput{
		AnonymousUserID: anotherAnon.User.ID,
		PermanentToken:  anonRes.Token, // already revoked
	})
	if !errors.Is(err, anonymous.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials on revoked token, got %v", err)
	}
}

func TestAnonymous_ExpirationAndCleanup(t *testing.T) {
	ctx := context.Background()
	// Configure short identity TTL for testing expiration
	h := setupHarness(t, anonymous.WithIdentityTTL(10*time.Millisecond))

	authRes, err := h.anon.Authenticate(ctx, anonymous.AuthenticateInput{})
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}

	// Wait for identity to expire
	time.Sleep(20 * time.Millisecond)

	// IsAnonymous should report false
	isAnon, err := h.anon.IsAnonymous(ctx, authRes.User.ID)
	if err != nil || isAnon {
		t.Fatalf("expected expired identity to not be active, got %v", isAnon)
	}

	// Conversion should fail on expired identity
	_, err = h.anon.Convert(ctx, anonymous.ConvertInput{
		AnonymousUserID: authRes.User.ID,
		Email:           "expired@example.com",
		Password:        "Password123!",
	})
	if !errors.Is(err, anonymous.ErrAnonymousExpired) {
		t.Fatalf("expected ErrAnonymousExpired, got %v", err)
	}

	// Run cleanup
	cleanupRes, err := h.anon.Cleanup(ctx, time.Now().Add(time.Second))
	if err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}

	if cleanupRes.IdentitiesDeleted != 1 {
		t.Fatalf("expected 1 identity deleted, got %d", cleanupRes.IdentitiesDeleted)
	}
	if cleanupRes.UsersDeleted != 1 {
		t.Fatalf("expected 1 core user deleted, got %d", cleanupRes.UsersDeleted)
	}

	// Verify identity is gone
	_, err = h.anon.GetIdentity(ctx, authRes.User.ID)
	if !errors.Is(err, anonymous.ErrAnonymousNotFound) {
		t.Fatalf("expected ErrAnonymousNotFound after cleanup, got %v", err)
	}
}

func TestAnonymous_Hooks(t *testing.T) {
	ctx := context.Background()
	hooks := anonymous.NewHooks()

	var beforeCreateCalled, afterCreateCalled bool
	var beforeConvertCalled, afterConvertCalled bool

	hooks.BeforeCreate(func(ctx context.Context, in *anonymous.AuthenticateInput) error {
		beforeCreateCalled = true
		if in.Metadata == nil {
			in.Metadata = make(map[string]string)
		}
		in.Metadata["hook_injected"] = "true"
		return nil
	})

	hooks.AfterCreate(func(ctx context.Context, res *anonymous.AuthResult) {
		afterCreateCalled = true
	})

	hooks.BeforeConvert(func(ctx context.Context, in *anonymous.ConvertInput) error {
		beforeConvertCalled = true
		return nil
	})

	hooks.AfterConvert(func(ctx context.Context, res *anonymous.ConvertResult) {
		afterConvertCalled = true
	})

	h := setupHarness(t, anonymous.WithHooks(hooks))

	res, err := h.anon.Authenticate(ctx, anonymous.AuthenticateInput{})
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}

	if !beforeCreateCalled || !afterCreateCalled {
		t.Fatal("expected create hooks to have run")
	}
	if res.Identity.Metadata["hook_injected"] != "true" {
		t.Fatal("expected hook injected metadata")
	}

	_, err = h.anon.Convert(ctx, anonymous.ConvertInput{
		AnonymousUserID: res.User.ID,
		Email:           "hookuser@example.com",
		Password:        "ValidPassword123!",
	})
	if err != nil {
		t.Fatalf("Convert failed: %v", err)
	}

	if !beforeConvertCalled || !afterConvertCalled {
		t.Fatal("expected convert hooks to have run")
	}
}

func TestAnonymous_EventsPublished(t *testing.T) {
	ctx := context.Background()
	h := setupHarness(t)

	authRes, err := h.anon.Authenticate(ctx, anonymous.AuthenticateInput{})
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}

	_, err = h.anon.Convert(ctx, anonymous.ConvertInput{
		AnonymousUserID: authRes.User.ID,
		Email:           "eventuser@example.com",
		Password:        "ValidPassword123!",
	})
	if err != nil {
		t.Fatalf("Convert failed: %v", err)
	}

	var foundCreated, foundConverted bool
	for _, ev := range h.events {
		if ev.Name == anonymous.EventAnonymousCreated {
			foundCreated = true
		}
		if ev.Name == anonymous.EventAnonymousConverted {
			foundConverted = true
		}
	}

	if !foundCreated {
		t.Error("expected EventAnonymousCreated to be published")
	}
	if !foundConverted {
		t.Error("expected EventAnonymousConverted to be published")
	}
}
