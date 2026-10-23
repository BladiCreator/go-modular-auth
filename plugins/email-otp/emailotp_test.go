package emailotp_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapter/memory"
	corecache "github.com/BladiCreator/go-modular-auth/cache"
	cachememory "github.com/BladiCreator/go-modular-auth/cache/memory"
	"github.com/BladiCreator/go-modular-auth/email"
	emailmemory "github.com/BladiCreator/go-modular-auth/email/memory"
	emailotp "github.com/BladiCreator/go-modular-auth/plugins/email-otp"
	"github.com/BladiCreator/go-modular-auth/plugins/email-otp/cache"
	"github.com/BladiCreator/go-modular-auth/plugins/email-otp/plugins"
	"github.com/BladiCreator/go-modular-auth/store"
	"github.com/BladiCreator/go-modular-auth/user"
)

type testHarness struct {
	auth        *auth.Auth
	store       store.Store
	cache       corecache.Cache
	emailSender *emailmemory.Sender
	plugin      *emailotp.Module
	svc         emailotp.EmailOTP
}

func setupTest(t *testing.T, opts ...emailotp.Option) *testHarness {
	t.Helper()

	ad := adaptermem.New()
	c := cachememory.New()
	sender := emailmemory.New()

	baseOpts := []emailotp.Option{
		emailotp.WithEmailSender(sender),
		emailotp.WithTTL(5 * time.Minute),
		emailotp.WithMaxAttempts(3),
		emailotp.WithOTPLength(6),
		emailotp.WithAllowSignUp(true),
	}
	baseOpts = append(baseOpts, opts...)

	mod := emailotp.New(baseOpts...)

	a, err := auth.New(auth.Config{
		Adapter: ad,
		Cache:   c,
		Email:   sender,
		Plugins: []auth.PluginModule{mod},
	})
	if err != nil {
		t.Fatalf("failed to create auth engine: %v", err)
	}

	svc, err := auth.Get[plugins.EmailOTP](a)
	if err != nil {
		t.Fatalf("failed to retrieve EmailOTP capability: %v", err)
	}

	return &testHarness{
		auth:        a,
		store:       a.Store(),
		cache:       c,
		emailSender: sender,
		plugin:      mod,
		svc:         svc,
	}
}

func extractOTPFromMessage(msg email.Message) string {
	// Our default message puts the code after "Your verification code is: "
	prefix := "Your verification code is: "
	idx := len(prefix)
	if len(msg.Text) >= idx+6 {
		return msg.Text[idx : idx+6]
	}
	return ""
}

func TestEmailOTP_PluginRegistration(t *testing.T) {
	h := setupTest(t)

	if h.svc == nil {
		t.Fatal("expected non-nil EmailOTP capability")
	}

	// Verify both alias and direct package lookup resolve
	directSvc, err := auth.Get[emailotp.EmailOTP](h.auth)
	if err != nil {
		t.Fatalf("failed to retrieve direct EmailOTP capability: %v", err)
	}
	if directSvc != h.svc {
		t.Fatal("expected direct and plugin alias to reference the same instance")
	}
}

func TestEmailOTP_MissingEmailSender(t *testing.T) {
	ad := adaptermem.New()
	mod := emailotp.New() // no email sender supplied

	_, err := auth.New(auth.Config{
		Adapter: ad,
		Plugins: []auth.PluginModule{mod},
	})
	if !errors.Is(err, emailotp.ErrEmailSenderRequired) {
		t.Fatalf("expected ErrEmailSenderRequired, got %v", err)
	}
}

func TestEmailOTP_Request_Validation(t *testing.T) {
	h := setupTest(t)
	ctx := context.Background()

	// Empty email
	err := h.svc.Request(ctx, emailotp.RequestInput{Email: ""})
	if !errors.Is(err, emailotp.ErrEmailRequired) {
		t.Fatalf("expected ErrEmailRequired, got %v", err)
	}

	// Invalid email syntax
	err = h.svc.Request(ctx, emailotp.RequestInput{Email: "invalid-email-format"})
	if !errors.Is(err, emailotp.ErrInvalidEmail) {
		t.Fatalf("expected ErrInvalidEmail, got %v", err)
	}
}

func TestEmailOTP_Request_PreventUserEnumeration(t *testing.T) {
	// When AllowSignUp is false, unknown emails must return nil without dispatching email
	h := setupTest(t, emailotp.WithAllowSignUp(false))
	ctx := context.Background()

	err := h.svc.Request(ctx, emailotp.RequestInput{Email: "unknown@example.com"})
	if err != nil {
		t.Fatalf("expected nil to prevent enumeration, got %v", err)
	}

	if len(h.emailSender.Messages()) != 0 {
		t.Fatalf("expected 0 emails sent for unknown user, got %d", len(h.emailSender.Messages()))
	}
}

func TestEmailOTP_RequestAndVerify_AutoSignUp(t *testing.T) {
	h := setupTest(t, emailotp.WithAllowSignUp(true))
	ctx := context.Background()

	emailAddr := "newuser@example.com"
	err := h.svc.Request(ctx, emailotp.RequestInput{Email: emailAddr})
	if err != nil {
		t.Fatalf("unexpected request error: %v", err)
	}

	msgs := h.emailSender.Messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 email, got %d", len(msgs))
	}
	code := extractOTPFromMessage(msgs[0])
	if len(code) != 6 {
		t.Fatalf("expected 6-digit code, got %q", code)
	}

	res, err := h.svc.Verify(ctx, emailotp.VerifyInput{
		Email: emailAddr,
		Code:  code,
	})
	if err != nil {
		t.Fatalf("unexpected verify error: %v", err)
	}

	if res.User == nil || res.Session == nil || res.Token == "" {
		t.Fatalf("incomplete AuthResult: %+v", res)
	}
	if res.User.Email != emailAddr {
		t.Fatalf("expected email %q, got %q", emailAddr, res.User.Email)
	}
	if !res.User.EmailVerified {
		t.Fatal("expected EmailVerified to be true")
	}

	// Verify User and Account persisted in Core Store
	u, err := h.store.Users().GetByEmail(ctx, emailAddr)
	if err != nil {
		t.Fatalf("expected user to be persisted: %v", err)
	}
	if u.ID != res.User.ID {
		t.Fatalf("user ID mismatch: %q vs %q", u.ID, res.User.ID)
	}
}

func TestEmailOTP_Verify_ExistingUser(t *testing.T) {
	h := setupTest(t)
	ctx := context.Background()

	// Pre-create user in Core Store
	existing := &user.User{
		ID:            "user-123",
		Email:         "existing@example.com",
		EmailVerified: false,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	if err := h.store.Users().Create(ctx, existing); err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	err := h.svc.Request(ctx, emailotp.RequestInput{Email: existing.Email})
	if err != nil {
		t.Fatalf("request error: %v", err)
	}

	code := extractOTPFromMessage(h.emailSender.Messages()[0])

	res, err := h.svc.Verify(ctx, emailotp.VerifyInput{
		Email: existing.Email,
		Code:  code,
	})
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}

	if res.User.ID != existing.ID {
		t.Fatalf("expected user ID %s, got %s", existing.ID, res.User.ID)
	}

	// User should now be marked email verified
	updatedUser, _ := h.store.Users().GetByID(ctx, existing.ID)
	if !updatedUser.EmailVerified {
		t.Fatal("expected user to be marked email verified")
	}
}

func TestEmailOTP_Verify_SingleUseAndReplayPrevention(t *testing.T) {
	h := setupTest(t)
	ctx := context.Background()

	emailAddr := "replay@example.com"
	if err := h.svc.Request(ctx, emailotp.RequestInput{Email: emailAddr}); err != nil {
		t.Fatalf("request error: %v", err)
	}

	code := extractOTPFromMessage(h.emailSender.Messages()[0])

	// First verification: success
	res, err := h.svc.Verify(ctx, emailotp.VerifyInput{
		Email: emailAddr,
		Code:  code,
	})
	if err != nil {
		t.Fatalf("first verification failed: %v", err)
	}
	if res.User == nil {
		t.Fatal("expected authenticated user")
	}

	// Second verification with identical code: must be rejected (single-use guarantee)
	_, err = h.svc.Verify(ctx, emailotp.VerifyInput{
		Email: emailAddr,
		Code:  code,
	})
	if err == nil {
		t.Fatal("expected second verification to fail")
	}
	if !errors.Is(err, emailotp.ErrInvalidCode) && !errors.Is(err, emailotp.ErrCodeAlreadyUsed) {
		t.Fatalf("expected ErrInvalidCode or ErrCodeAlreadyUsed, got: %v", err)
	}
}

func TestEmailOTP_Verify_MaxAttemptsLockout(t *testing.T) {
	// MaxAttempts = 3
	h := setupTest(t, emailotp.WithMaxAttempts(3))
	ctx := context.Background()

	emailAddr := "bruteforce@example.com"
	if err := h.svc.Request(ctx, emailotp.RequestInput{Email: emailAddr}); err != nil {
		t.Fatalf("request error: %v", err)
	}

	correctCode := extractOTPFromMessage(h.emailSender.Messages()[0])
	wrongCode := "000000"
	if correctCode == wrongCode {
		wrongCode = "999999"
	}

	// Attempt 1: wrong code
	_, err := h.svc.Verify(ctx, emailotp.VerifyInput{Email: emailAddr, Code: wrongCode})
	if !errors.Is(err, emailotp.ErrInvalidCode) {
		t.Fatalf("attempt 1: expected ErrInvalidCode, got %v", err)
	}

	// Attempt 2: wrong code
	_, err = h.svc.Verify(ctx, emailotp.VerifyInput{Email: emailAddr, Code: wrongCode})
	if !errors.Is(err, emailotp.ErrInvalidCode) {
		t.Fatalf("attempt 2: expected ErrInvalidCode, got %v", err)
	}

	// Attempt 3: wrong code -> hits MaxAttempts (3), returns ErrMaxAttemptsExceeded
	_, err = h.svc.Verify(ctx, emailotp.VerifyInput{Email: emailAddr, Code: wrongCode})
	if !errors.Is(err, emailotp.ErrMaxAttemptsExceeded) {
		t.Fatalf("attempt 3: expected ErrMaxAttemptsExceeded, got %v", err)
	}

	// Attempt 4: even with the CORRECT code, must remain locked out!
	_, err = h.svc.Verify(ctx, emailotp.VerifyInput{Email: emailAddr, Code: correctCode})
	if !errors.Is(err, emailotp.ErrMaxAttemptsExceeded) {
		t.Fatalf("attempt 4 with correct code: expected ErrMaxAttemptsExceeded, got %v", err)
	}
}

func TestEmailOTP_Verify_ExpiredCode(t *testing.T) {
	// Set very short TTL
	h := setupTest(t, emailotp.WithTTL(10*time.Millisecond))
	ctx := context.Background()

	emailAddr := "expired@example.com"
	if err := h.svc.Request(ctx, emailotp.RequestInput{Email: emailAddr}); err != nil {
		t.Fatalf("request error: %v", err)
	}

	code := extractOTPFromMessage(h.emailSender.Messages()[0])

	// Wait for expiration
	time.Sleep(20 * time.Millisecond)

	_, err := h.svc.Verify(ctx, emailotp.VerifyInput{
		Email: emailAddr,
		Code:  code,
	})
	if err == nil {
		t.Fatal("expected expired OTP to be rejected")
	}
	if !errors.Is(err, emailotp.ErrCodeExpired) && !errors.Is(err, emailotp.ErrInvalidCode) {
		t.Fatalf("expected ErrCodeExpired or ErrInvalidCode, got %v", err)
	}
}

func TestEmailOTP_Concurrency_RaceConditionSingleUse(t *testing.T) {
	h := setupTest(t)
	ctx := context.Background()

	emailAddr := "race@example.com"
	if err := h.svc.Request(ctx, emailotp.RequestInput{Email: emailAddr}); err != nil {
		t.Fatalf("request error: %v", err)
	}

	code := extractOTPFromMessage(h.emailSender.Messages()[0])

	const concurrency = 10
	var wg sync.WaitGroup
	wg.Add(concurrency)

	type result struct {
		authRes *auth.AuthResult
		err     error
	}
	results := make([]result, concurrency)

	// Launch concurrent verify requests with the exact same valid OTP code
	for i := 0; i < concurrency; i++ {
		go func(idx int) {
			defer wg.Done()
			res, err := h.svc.Verify(ctx, emailotp.VerifyInput{
				Email: emailAddr,
				Code:  code,
			})
			results[idx] = result{authRes: res, err: err}
		}(i)
	}

	wg.Wait()

	successCount := 0
	failureCount := 0
	for _, r := range results {
		if r.err == nil && r.authRes != nil {
			successCount++
		} else {
			failureCount++
		}
	}

	// CRITICAL TEST: Exactly ONE goroutine may consume the OTP
	if successCount != 1 {
		t.Fatalf("expected exactly 1 successful consumption, got %d successes and %d failures", successCount, failureCount)
	}
	if failureCount != concurrency-1 {
		t.Fatalf("expected %d failures, got %d", concurrency-1, failureCount)
	}
}

func TestEmailOTP_RateLimitAndCooldown(t *testing.T) {
	h := setupTest(t,
		emailotp.WithRateLimit(3, 1*time.Minute, 200*time.Millisecond),
	)
	ctx := context.Background()
	emailAddr := "ratelimit@example.com"

	// Request 1: success
	if err := h.svc.Request(ctx, emailotp.RequestInput{Email: emailAddr}); err != nil {
		t.Fatalf("request 1 failed: %v", err)
	}

	// Immediate Request 2: should trigger Cooldown
	err := h.svc.Request(ctx, emailotp.RequestInput{Email: emailAddr})
	if !errors.Is(err, emailotp.ErrCooldownActive) {
		t.Fatalf("expected ErrCooldownActive, got %v", err)
	}

	// Wait for cooldown to elapse
	time.Sleep(250 * time.Millisecond)

	// Request 2 after cooldown: success
	if err := h.svc.Request(ctx, emailotp.RequestInput{Email: emailAddr}); err != nil {
		t.Fatalf("request 2 after cooldown failed: %v", err)
	}

	time.Sleep(250 * time.Millisecond)

	// Request 3: success (total requests = 3, reaches Max: 3)
	if err := h.svc.Request(ctx, emailotp.RequestInput{Email: emailAddr}); err != nil {
		t.Fatalf("request 3 failed: %v", err)
	}

	time.Sleep(250 * time.Millisecond)

	// Request 4: exceeds Rate Limit Max (3 per minute)
	err = h.svc.Request(ctx, emailotp.RequestInput{Email: emailAddr})
	if !errors.Is(err, emailotp.ErrRateLimitExceeded) {
		t.Fatalf("expected ErrRateLimitExceeded, got %v", err)
	}
}

func TestEmailOTP_CacheFailurePolicy(t *testing.T) {
	// Test FailClosed vs FailOpen
	limiterClosed := cache.NewLimiter(nil, cache.FailClosed, time.Now)
	ok, err := limiterClosed.CheckRateLimit(context.Background(), "user@example.com", 5, time.Minute)
	if !ok || err != nil {
		t.Fatalf("expected in-memory fallback to succeed: ok=%v, err=%v", ok, err)
	}

	limiterOpen := cache.NewLimiter(nil, cache.FailOpen, time.Now)
	ok, err = limiterOpen.CheckRateLimit(context.Background(), "user@example.com", 5, time.Minute)
	if !ok || err != nil {
		t.Fatalf("expected in-memory fallback to succeed: ok=%v, err=%v", ok, err)
	}
}

func TestEmailOTP_Revocation(t *testing.T) {
	h := setupTest(t)
	ctx := context.Background()
	emailAddr := "revoke@example.com"

	if err := h.svc.Request(ctx, emailotp.RequestInput{Email: emailAddr}); err != nil {
		t.Fatalf("request failed: %v", err)
	}

	code := extractOTPFromMessage(h.emailSender.Messages()[0])

	// Explicitly revoke
	if err := h.svc.Revoke(ctx, emailAddr); err != nil {
		t.Fatalf("revoke failed: %v", err)
	}

	// Attempt verification with code issued before revocation
	_, err := h.svc.Verify(ctx, emailotp.VerifyInput{
		Email: emailAddr,
		Code:  code,
	})
	if !errors.Is(err, emailotp.ErrInvalidCode) {
		t.Fatalf("expected ErrInvalidCode after revocation, got %v", err)
	}
}

func TestEmailOTP_EventsEmitted(t *testing.T) {
	h := setupTest(t)
	ctx := context.Background()

	var (
		mu           sync.Mutex
		requestedEvt bool
		verifiedEvt  bool
		rejectedEvt  bool
	)

	h.auth.Events().Subscribe(emailotp.EventOTPRequested, func(ctx context.Context, e auth.Event) {
		mu.Lock()
		requestedEvt = true
		mu.Unlock()
	})
	h.auth.Events().Subscribe(emailotp.EventOTPVerified, func(ctx context.Context, e auth.Event) {
		mu.Lock()
		verifiedEvt = true
		mu.Unlock()
	})
	h.auth.Events().Subscribe(emailotp.EventOTPRejected, func(ctx context.Context, e auth.Event) {
		mu.Lock()
		rejectedEvt = true
		mu.Unlock()
	})

	emailAddr := "events@example.com"
	_ = h.svc.Request(ctx, emailotp.RequestInput{Email: emailAddr})

	// Reject event
	_, _ = h.svc.Verify(ctx, emailotp.VerifyInput{Email: emailAddr, Code: "000000"})

	// Verify event
	code := extractOTPFromMessage(h.emailSender.Messages()[0])
	_, _ = h.svc.Verify(ctx, emailotp.VerifyInput{Email: emailAddr, Code: code})

	mu.Lock()
	defer mu.Unlock()

	if !requestedEvt {
		t.Error("expected EventOTPRequested to be published")
	}
	if !rejectedEvt {
		t.Error("expected EventOTPRejected to be published")
	}
	if !verifiedEvt {
		t.Error("expected EventOTPVerified to be published")
	}
}
