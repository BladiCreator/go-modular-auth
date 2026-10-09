package magiclink_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth-magiclink"
	"github.com/BladiCreator/go-modular-auth-magiclink/plugins"
	mememail "github.com/BladiCreator/go-modular-auth/email/memory"
	"github.com/BladiCreator/go-modular-auth/password"
	memstore "github.com/BladiCreator/go-modular-auth/store/memory"
)

var fastHasher = password.NewArgon2id(password.Argon2idParams{
	Memory:      64 * 1024,
	Iterations:  1,
	Parallelism: 1,
	KeyLength:   32,
	SaltLength:  16,
})

func setupTestAuth(t *testing.T, opts ...magiclink.Option) (*auth.Auth, *mememail.Sender, magiclink.MagicLink) {
	t.Helper()
	emailSender := mememail.New()
	store := memstore.New()

	pluginModule := magiclink.New(opts...)

	a, err := auth.New(auth.Config{
		Store:   store,
		Email:   emailSender,
		Hasher:  fastHasher,
		Plugins: []auth.PluginModule{pluginModule},
	})
	if err != nil {
		t.Fatalf("auth.New failed: %v", err)
	}

	cap, err := auth.Get[magiclink.MagicLink](a)
	if err != nil {
		t.Fatalf("auth.Get[magiclink.MagicLink](a) failed: %v", err)
	}

	return a, emailSender, cap
}

func extractTokenFromEmail(body string) string {
	lines := strings.Split(body, "\n")
	for i, line := range lines {
		if strings.Contains(line, "Use the following token to sign in:") && i+2 < len(lines) {
			return strings.TrimSpace(lines[i+2])
		}
	}
	return ""
}

func TestPluginRegistration(t *testing.T) {
	a, _, cap := setupTestAuth(t)

	if cap == nil {
		t.Fatal("expected non-nil capability")
	}

	// Verify lookup with plugins alias works
	pluginsCap, err := auth.Get[plugins.MagicLink](a)
	if err != nil {
		t.Fatalf("auth.Get[plugins.MagicLink](a) failed: %v", err)
	}
	if pluginsCap == nil {
		t.Fatal("expected non-nil capability via plugins alias")
	}

	// Verify missing email sender returns error during Init
	_, err = auth.New(auth.Config{
		Store:   memstore.New(),
		Hasher:  fastHasher,
		Plugins: []auth.PluginModule{magiclink.New()},
	})
	if !errors.Is(err, magiclink.ErrEmailSenderRequired) {
		t.Fatalf("expected ErrEmailSenderRequired, got: %v", err)
	}
}

func TestMagicLinkAuthenticationFlow_ExistingUser(t *testing.T) {
	ctx := context.Background()
	a, mailer, ml := setupTestAuth(t,
		magiclink.WithBaseURL("https://example.com/login/verify"),
		magiclink.WithTTL(10*time.Minute),
	)

	// Create existing user
	signUpRes, err := a.SignUp(ctx, auth.SignUpInput{
		Email:    "alice@example.com",
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("SignUp failed: %v", err)
	}
	userID := signUpRes.User.ID

	// Subscribe to events
	var requestedEvents []auth.Event
	var consumedEvents []auth.Event
	var evMu sync.Mutex

	a.Events().Subscribe(magiclink.EventMagicLinkRequested, func(ctx context.Context, e auth.Event) {
		evMu.Lock()
		defer evMu.Unlock()
		requestedEvents = append(requestedEvents, e)
	})
	a.Events().Subscribe(magiclink.EventMagicLinkConsumed, func(ctx context.Context, e auth.Event) {
		evMu.Lock()
		defer evMu.Unlock()
		consumedEvents = append(consumedEvents, e)
	})

	// Request magic link
	err = ml.Request(ctx, magiclink.RequestInput{Email: "alice@example.com"})
	if err != nil {
		t.Fatalf("ml.Request failed: %v", err)
	}

	// Check sent email
	msg, ok := mailer.Last()
	if !ok {
		t.Fatal("expected email to be sent")
	}
	if msg.To != "alice@example.com" {
		t.Fatalf("expected email to alice@example.com, got %q", msg.To)
	}
	if !strings.Contains(msg.Text, "https://example.com/login/verify?token=") {
		t.Fatalf("expected verification URL in email body, got:\n%s", msg.Text)
	}

	token := extractTokenFromEmail(msg.Text)
	if token == "" {
		t.Fatalf("failed to extract token from email:\n%s", msg.Text)
	}

	// Verify requested event
	evMu.Lock()
	if len(requestedEvents) != 1 {
		t.Fatalf("expected 1 requested event, got %d", len(requestedEvents))
	}
	reqPayload := requestedEvents[0].Payload.(magiclink.MagicLinkRequestedPayload)
	if reqPayload.Email != "alice@example.com" || reqPayload.Subject != userID {
		t.Fatalf("unexpected event payload: %+v", reqPayload)
	}
	evMu.Unlock()

	// Authenticate with the token
	authRes, err := ml.Authenticate(ctx, magiclink.AuthenticateInput{
		Token: token,
		Session: auth.SessionOptions{
			IPAddress: "127.0.0.1",
			UserAgent: "TestClient/1.0",
		},
	})
	if err != nil {
		t.Fatalf("ml.Authenticate failed: %v", err)
	}

	if authRes.User.ID != userID {
		t.Fatalf("expected user ID %q, got %q", userID, authRes.User.ID)
	}
	if authRes.Token == "" || authRes.Session == nil {
		t.Fatal("expected valid session and session token")
	}

	// Verify session is valid in Core
	sessRes, err := a.RequireSession(ctx, authRes.Token)
	if err != nil {
		t.Fatalf("RequireSession failed: %v", err)
	}
	if sessRes.User.ID != userID {
		t.Fatalf("session user mismatch: %q vs %q", sessRes.User.ID, userID)
	}

	// Verify consumed event
	evMu.Lock()
	if len(consumedEvents) != 1 {
		t.Fatalf("expected 1 consumed event, got %d", len(consumedEvents))
	}
	consumedPayload := consumedEvents[0].Payload.(magiclink.MagicLinkConsumedPayload)
	if consumedPayload.UserID != userID || consumedPayload.Email != "alice@example.com" {
		t.Fatalf("unexpected consumed payload: %+v", consumedPayload)
	}
	evMu.Unlock()
}

func TestSingleUseAndReplayPrevention(t *testing.T) {
	ctx := context.Background()
	a, mailer, ml := setupTestAuth(t)

	_, err := a.SignUp(ctx, auth.SignUpInput{
		Email:    "bob@example.com",
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("SignUp failed: %v", err)
	}

	if err := ml.Request(ctx, magiclink.RequestInput{Email: "bob@example.com"}); err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	msg, _ := mailer.Last()
	token := extractTokenFromEmail(msg.Text)

	// First consumption: success
	_, err = ml.Authenticate(ctx, magiclink.AuthenticateInput{Token: token})
	if err != nil {
		t.Fatalf("first Authenticate failed: %v", err)
	}

	// Second consumption: MUST fail (single-use enforced atomically)
	_, err = ml.Authenticate(ctx, magiclink.AuthenticateInput{Token: token})
	if !errors.Is(err, magiclink.ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken on second consume, got %v", err)
	}
}

func TestExpirationEnforcement(t *testing.T) {
	ctx := context.Background()
	fakeNow := time.Now()
	clock := func() time.Time { return fakeNow }

	emailSender := mememail.New()
	store := memstore.New()

	a, err := auth.New(auth.Config{
		Store:   store,
		Email:   emailSender,
		Hasher:  fastHasher,
		Now:     clock,
		Plugins: []auth.PluginModule{magiclink.New(magiclink.WithTTL(5 * time.Minute))},
	})
	if err != nil {
		t.Fatal(err)
	}

	ml, _ := auth.Get[magiclink.MagicLink](a)

	_, err = a.SignUp(ctx, auth.SignUpInput{
		Email:    "charlie@example.com",
		Password: "password123",
	})
	if err != nil {
		t.Fatal(err)
	}

	_ = ml.Request(ctx, magiclink.RequestInput{Email: "charlie@example.com"})
	msg, _ := emailSender.Last()
	token := extractTokenFromEmail(msg.Text)

	// Advance clock beyond 5 minute TTL
	fakeNow = fakeNow.Add(10 * time.Minute)

	_, err = ml.Authenticate(ctx, magiclink.AuthenticateInput{Token: token})
	if !errors.Is(err, magiclink.ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for expired token, got %v", err)
	}
}

func TestConcurrentDoubleConsumption(t *testing.T) {
	ctx := context.Background()
	a, mailer, ml := setupTestAuth(t)

	_, err := a.SignUp(ctx, auth.SignUpInput{
		Email:    "dave@example.com",
		Password: "password123",
	})
	if err != nil {
		t.Fatal(err)
	}

	_ = ml.Request(ctx, magiclink.RequestInput{Email: "dave@example.com"})
	msg, _ := mailer.Last()
	token := extractTokenFromEmail(msg.Text)

	const concurrency = 20
	var wg sync.WaitGroup
	var successCount int64
	var failureCount int64

	start := make(chan struct{})

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := ml.Authenticate(ctx, magiclink.AuthenticateInput{Token: token})
			if err == nil {
				atomic.AddInt64(&successCount, 1)
			} else if errors.Is(err, magiclink.ErrInvalidToken) {
				atomic.AddInt64(&failureCount, 1)
			}
		}()
	}

	close(start)
	wg.Wait()

	if successCount != 1 {
		t.Fatalf("expected exactly 1 successful consumption, got %d", successCount)
	}
	if failureCount != concurrency-1 {
		t.Fatalf("expected %d failures, got %d", concurrency-1, failureCount)
	}
}

func TestUserEnumerationPrevention(t *testing.T) {
	ctx := context.Background()
	_, mailer, ml := setupTestAuth(t, magiclink.WithAllowSignUp(false))

	// Request magic link for an UNREGISTERED email
	err := ml.Request(ctx, magiclink.RequestInput{Email: "nonexistent@example.com"})
	if err != nil {
		t.Fatalf("Request leaked user non-existence with error: %v", err)
	}

	// No email should be sent, but caller receives success
	if len(mailer.Messages()) != 0 {
		t.Fatalf("expected 0 emails sent for non-existent user, got %d", len(mailer.Messages()))
	}
}

func TestAutoSignUp(t *testing.T) {
	ctx := context.Background()
	a, mailer, ml := setupTestAuth(t, magiclink.WithAllowSignUp(true))

	// Request magic link for an UNREGISTERED email with AllowSignUp = true
	err := ml.Request(ctx, magiclink.RequestInput{Email: "newcomer@example.com"})
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	msg, ok := mailer.Last()
	if !ok {
		t.Fatal("expected email to be sent for new user signup")
	}
	token := extractTokenFromEmail(msg.Text)

	// Authenticate
	res, err := ml.Authenticate(ctx, magiclink.AuthenticateInput{Token: token})
	if err != nil {
		t.Fatalf("Authenticate failed during auto signup: %v", err)
	}

	if res.User.Email != "newcomer@example.com" {
		t.Fatalf("expected user email newcomer@example.com, got %q", res.User.Email)
	}
	if !res.User.EmailVerified {
		t.Fatal("expected user email to be verified on signup")
	}

	// Verify user is in Store
	u, err := a.Store().Users().GetByEmail(ctx, "newcomer@example.com")
	if err != nil {
		t.Fatalf("user was not persisted in store: %v", err)
	}
	if u.ID != res.User.ID {
		t.Fatalf("stored user ID %q does not match %q", u.ID, res.User.ID)
	}
}

func TestRateLimitingAndCooldown(t *testing.T) {
	ctx := context.Background()
	a, _, ml := setupTestAuth(t,
		magiclink.WithRateLimit(magiclink.RateLimitConfig{
			Enabled:  true,
			Max:      2,
			Window:   10 * time.Minute,
			Cooldown: 200 * time.Millisecond,
		}),
	)

	_, err := a.SignUp(ctx, auth.SignUpInput{
		Email:    "frank@example.com",
		Password: "password123",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Request 1: success
	if err := ml.Request(ctx, magiclink.RequestInput{Email: "frank@example.com"}); err != nil {
		t.Fatalf("request 1 failed: %v", err)
	}

	// Immediate request 2: Cooldown active
	err = ml.Request(ctx, magiclink.RequestInput{Email: "frank@example.com"})
	if !errors.Is(err, magiclink.ErrCooldownActive) {
		t.Fatalf("expected ErrCooldownActive, got: %v", err)
	}

	// Wait past cooldown
	time.Sleep(250 * time.Millisecond)

	// Request 2 (allowed count = 2): success
	if err := ml.Request(ctx, magiclink.RequestInput{Email: "frank@example.com"}); err != nil {
		t.Fatalf("request 2 after cooldown failed: %v", err)
	}

	// Wait past cooldown
	time.Sleep(250 * time.Millisecond)

	// Request 3 (limit = 2): Rate limit exceeded
	err = ml.Request(ctx, magiclink.RequestInput{Email: "frank@example.com"})
	if !errors.Is(err, magiclink.ErrRateLimitExceeded) {
		t.Fatalf("expected ErrRateLimitExceeded, got: %v", err)
	}
}

func TestRevokePreviousOnRequest(t *testing.T) {
	ctx := context.Background()
	a, mailer, ml := setupTestAuth(t,
		magiclink.WithRevokePreviousOnRequest(true),
	)

	_, err := a.SignUp(ctx, auth.SignUpInput{
		Email:    "grace@example.com",
		Password: "password123",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Request token 1
	_ = ml.Request(ctx, magiclink.RequestInput{Email: "grace@example.com"})
	msg1, _ := mailer.Last()
	token1 := extractTokenFromEmail(msg1.Text)

	// Request token 2
	_ = ml.Request(ctx, magiclink.RequestInput{Email: "grace@example.com"})
	msg2, _ := mailer.Last()
	token2 := extractTokenFromEmail(msg2.Text)

	// Token 1 should be revoked
	_, err = ml.Authenticate(ctx, magiclink.AuthenticateInput{Token: token1})
	if !errors.Is(err, magiclink.ErrInvalidToken) {
		t.Fatalf("expected token1 to be revoked, got %v", err)
	}

	// Token 2 should succeed
	_, err = ml.Authenticate(ctx, magiclink.AuthenticateInput{Token: token2})
	if err != nil {
		t.Fatalf("expected token2 to authenticate successfully, got %v", err)
	}
}

func TestCustomSecurityHooks(t *testing.T) {
	ctx := context.Background()
	hooks := magiclink.NewHooks()

	// Veto requests from disallowed domains
	hooks.BeforeRequest(func(ctx context.Context, in *magiclink.RequestInput) error {
		if strings.HasSuffix(in.Email, "@disallowed.com") {
			return errors.New("domain not allowed")
		}
		return nil
	})

	// Veto consumption if token is specific value
	hooks.BeforeConsume(func(ctx context.Context, in *magiclink.AuthenticateInput) error {
		if in.Token == "blocked-token" {
			return errors.New("blocked token")
		}
		return nil
	})

	_, _, ml := setupTestAuth(t, magiclink.WithHooks(hooks))

	err := ml.Request(ctx, magiclink.RequestInput{Email: "attacker@disallowed.com"})
	if err == nil || err.Error() != "domain not allowed" {
		t.Fatalf("expected hook to veto request, got: %v", err)
	}

	_, err = ml.Authenticate(ctx, magiclink.AuthenticateInput{Token: "blocked-token"})
	if err == nil || err.Error() != "blocked token" {
		t.Fatalf("expected hook to veto consume, got: %v", err)
	}
}

func TestRevokeExplicit(t *testing.T) {
	ctx := context.Background()
	a, mailer, ml := setupTestAuth(t)

	_, err := a.SignUp(ctx, auth.SignUpInput{
		Email:    "heidi@example.com",
		Password: "password123",
	})
	if err != nil {
		t.Fatal(err)
	}

	_ = ml.Request(ctx, magiclink.RequestInput{Email: "heidi@example.com"})
	msg, _ := mailer.Last()
	token := extractTokenFromEmail(msg.Text)

	// Explicitly revoke all tokens for heidi
	if err := ml.Revoke(ctx, "heidi@example.com"); err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}

	// Consumption should fail
	_, err = ml.Authenticate(ctx, magiclink.AuthenticateInput{Token: token})
	if !errors.Is(err, magiclink.ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken after explicit Revoke, got %v", err)
	}
}
