package twofactor_test

import (
	"context"
	"sync"
	"testing"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	twofactor "github.com/BladiCreator/go-modular-auth/plugins/twofactor"
	"github.com/BladiCreator/go-modular-auth/plugins/twofactor/plugins"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapter/memory"
	cachememory "github.com/BladiCreator/go-modular-auth/cache/memory"
)

func TestPlugin_RegistrationAndCapabilityResolution(t *testing.T) {
	ad := adaptermem.New()
	c := cachememory.New()
	mod := twofactor.New()

	engine, err := auth.New(auth.Config{
		Adapter: ad,
		Cache:   c,
		Plugins: []auth.PluginModule{mod},
	})
	if err != nil {
		t.Fatalf("auth.New failed: %v", err)
	}

	// Resolve via plugins.TwoFactor alias
	svc, err := auth.Get[plugins.TwoFactor](engine)
	if err != nil {
		t.Fatalf("auth.Get[plugins.TwoFactor](engine) failed: %v", err)
	}
	if svc == nil {
		t.Fatal("resolved TwoFactor service is nil")
	}

	// Also resolve via direct twofactor.TwoFactor
	svcDirect, err := auth.Get[twofactor.TwoFactor](engine)
	if err != nil {
		t.Fatalf("auth.Get[twofactor.TwoFactor](engine) failed: %v", err)
	}
	if svcDirect == nil {
		t.Fatal("resolved direct TwoFactor service is nil")
	}
}

func TestPlugin_EventsEmission(t *testing.T) {
	ad := adaptermem.New()
	c := cachememory.New()
	mod := twofactor.New()

	engine, err := auth.New(auth.Config{
		Adapter: ad,
		Cache:   c,
		Plugins: []auth.PluginModule{mod},
	})
	if err != nil {
		t.Fatalf("auth.New failed: %v", err)
	}

	svc, _ := auth.Get[plugins.TwoFactor](engine)
	ctx := context.Background()
	userID := "usr_events_test"

	var mu sync.Mutex
	var eventsReceived []auth.EventName

	engine.Events().Subscribe(twofactor.EventTwoFactorEnabled, func(ctx context.Context, e auth.Event) {
		mu.Lock()
		defer mu.Unlock()
		eventsReceived = append(eventsReceived, e.Name)
	})
	engine.Events().Subscribe(twofactor.EventTwoFactorVerified, func(ctx context.Context, e auth.Event) {
		mu.Lock()
		defer mu.Unlock()
		eventsReceived = append(eventsReceived, e.Name)
	})
	engine.Events().Subscribe(twofactor.EventTwoFactorDisabled, func(ctx context.Context, e auth.Event) {
		mu.Lock()
		defer mu.Unlock()
		eventsReceived = append(eventsReceived, e.Name)
	})

	// 1. Enroll and Confirm -> EventTwoFactorEnabled
	enrollment, err := svc.EnrollTOTP(ctx, userID)
	if err != nil {
		t.Fatalf("EnrollTOTP failed: %v", err)
	}
	now := time.Now().UTC()
	code, _ := twofactor.CalculateTOTP(enrollment.Secret, now.Unix()/30)
	if err := svc.ConfirmTOTP(ctx, userID, enrollment.FactorID, code); err != nil {
		t.Fatalf("ConfirmTOTP failed: %v", err)
	}

	// 2. Verify with next step or recovery code -> EventTwoFactorVerified
	recCodes, _ := svc.GenerateRecoveryCodes(ctx, userID, 2)
	_, err = svc.VerifyRecoveryCode(ctx, userID, recCodes[0])
	if err != nil {
		t.Fatalf("VerifyRecoveryCode failed: %v", err)
	}

	// 3. Disable -> EventTwoFactorDisabled
	if err := svc.Disable(ctx, userID); err != nil {
		t.Fatalf("Disable failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(eventsReceived) != 3 {
		t.Fatalf("expected 3 events, got %d: %v", len(eventsReceived), eventsReceived)
	}
	if eventsReceived[0] != twofactor.EventTwoFactorEnabled {
		t.Errorf("expected EventTwoFactorEnabled, got %v", eventsReceived[0])
	}
	if eventsReceived[1] != twofactor.EventTwoFactorVerified {
		t.Errorf("expected EventTwoFactorVerified, got %v", eventsReceived[1])
	}
	if eventsReceived[2] != twofactor.EventTwoFactorDisabled {
		t.Errorf("expected EventTwoFactorDisabled, got %v", eventsReceived[2])
	}
}

func TestPlugin_EnforceMFAOnSessionCreateHook(t *testing.T) {
	ad := adaptermem.New()
	c := cachememory.New()

	// Plugin with MFA enforcement turned on
	mod := twofactor.New(twofactor.WithEnforceMFAOnSignIn(true))

	engine, err := auth.New(auth.Config{
		Adapter: ad,
		Cache:   c,
		Plugins: []auth.PluginModule{mod},
	})
	if err != nil {
		t.Fatalf("auth.New failed: %v", err)
	}

	svc, _ := auth.Get[plugins.TwoFactor](engine)
	ctx := context.Background()

	// Create user in adapter
	now := time.Now().UTC()
	_, err = ad.Create(ctx, "users", map[string]any{
		"id":         "usr_mfa_hook",
		"email":      "mfa@example.com",
		"created_at": now,
		"updated_at": now,
	})
	if err != nil {
		t.Fatalf("failed to create user in adapter: %v", err)
	}

	// User without MFA can create session without restrictions
	sess1, err := engine.CreateSession(ctx, "usr_mfa_hook", auth.SessionOptions{})
	if err != nil {
		t.Fatalf("CreateSession failed for user without MFA: %v", err)
	}
	if sess1 == nil {
		t.Fatal("sess1 is nil")
	}

	// Now enable 2FA for this user
	enrollment, _ := svc.EnrollTOTP(ctx, "usr_mfa_hook")
	code, _ := twofactor.CalculateTOTP(enrollment.Secret, now.Unix()/30)
	_ = svc.ConfirmTOTP(ctx, "usr_mfa_hook", enrollment.FactorID, code)

	// Now attempt to create session with default AAL1 context -> should be blocked by hook!
	_, err = engine.CreateSession(ctx, "usr_mfa_hook", auth.SessionOptions{})
	if err == nil || err != twofactor.ErrAssuranceLevelInsufficient {
		t.Fatalf("expected ErrAssuranceLevelInsufficient when creating session without AAL2, got %v", err)
	}

	// Attempt with AAL2 in context -> succeeds!
	ctxAAL2 := twofactor.WithAssuranceLevel(ctx, twofactor.AAL2)
	sess2, err := engine.CreateSession(ctxAAL2, "usr_mfa_hook", auth.SessionOptions{})
	if err != nil {
		t.Fatalf("CreateSession with AAL2 context failed: %v", err)
	}
	if sess2 == nil {
		t.Fatal("sess2 is nil")
	}
}
