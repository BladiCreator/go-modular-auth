package twofactor_test

import (
	"context"
	"sync"
	"testing"
	"time"

	twofactor "github.com/BladiCreator/go-modular-auth-twofactor"
	"github.com/BladiCreator/go-modular-auth-twofactor/plugins"
	auth "github.com/BladiCreator/go-modular-auth"
	cachememory "github.com/BladiCreator/go-modular-auth/cache/memory"
	storememory "github.com/BladiCreator/go-modular-auth/store/memory"
	"github.com/BladiCreator/go-modular-auth/user"
)

func TestPlugin_RegistrationAndCapabilityResolution(t *testing.T) {
	s := storememory.New()
	c := cachememory.New()
	mod := twofactor.New()

	engine, err := auth.New(auth.Config{
		Store:   s,
		Cache:   c,
		Plugins: []auth.PluginModule{mod},
	})
	if err != nil {
		t.Fatalf("auth.New failed: %v", err)
	}

	// Resolve via plugins.TwoFactor alias
	svc, err := engine.Get[plugins.TwoFactor]()
	if err != nil {
		t.Fatalf("engine.Get[plugins.TwoFactor]() failed: %v", err)
	}
	if svc == nil {
		t.Fatal("resolved TwoFactor service is nil")
	}

	// Also resolve via direct twofactor.TwoFactor
	svcDirect, err := engine.Get[twofactor.TwoFactor]()
	if err != nil {
		t.Fatalf("engine.Get[twofactor.TwoFactor]() failed: %v", err)
	}
	if svcDirect == nil {
		t.Fatal("resolved direct TwoFactor service is nil")
	}
}

func TestPlugin_EventsEmission(t *testing.T) {
	s := storememory.New()
	c := cachememory.New()
	mod := twofactor.New()

	engine, err := auth.New(auth.Config{
		Store:   s,
		Cache:   c,
		Plugins: []auth.PluginModule{mod},
	})
	if err != nil {
		t.Fatalf("auth.New failed: %v", err)
	}

	svc, _ := engine.Get[plugins.TwoFactor]()
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
	s := storememory.New()
	c := cachememory.New()

	// Plugin with MFA enforcement turned on
	mod := twofactor.New(twofactor.WithEnforceMFAOnSignIn(true))

	engine, err := auth.New(auth.Config{
		Store:   s,
		Cache:   c,
		Plugins: []auth.PluginModule{mod},
	})
	if err != nil {
		t.Fatalf("auth.New failed: %v", err)
	}

	svc, _ := engine.Get[plugins.TwoFactor]()
	ctx := context.Background()

	// Create user in store
	u := &user.User{ID: "usr_mfa_hook", Email: "mfa@example.com"}
	_ = s.Users().Create(ctx, u)

	// User without MFA can create session without restrictions
	sess1, err := engine.CreateSession(ctx, u.ID, auth.SessionOptions{})
	if err != nil {
		t.Fatalf("CreateSession failed for user without MFA: %v", err)
	}
	if sess1 == nil {
		t.Fatal("sess1 is nil")
	}

	// Now enable 2FA for this user
	enrollment, _ := svc.EnrollTOTP(ctx, u.ID)
	now := time.Now().UTC()
	code, _ := twofactor.CalculateTOTP(enrollment.Secret, now.Unix()/30)
	_ = svc.ConfirmTOTP(ctx, u.ID, enrollment.FactorID, code)

	// Now attempt to create session with default AAL1 context -> should be blocked by hook!
	_, err = engine.CreateSession(ctx, u.ID, auth.SessionOptions{})
	if err == nil || err != twofactor.ErrAssuranceLevelInsufficient {
		t.Fatalf("expected ErrAssuranceLevelInsufficient when creating session without AAL2, got %v", err)
	}

	// Attempt with AAL2 in context -> succeeds!
	ctxAAL2 := twofactor.WithAssuranceLevel(ctx, twofactor.AAL2)
	sess2, err := engine.CreateSession(ctxAAL2, u.ID, auth.SessionOptions{})
	if err != nil {
		t.Fatalf("CreateSession with AAL2 context failed: %v", err)
	}
	if sess2 == nil {
		t.Fatal("sess2 is nil")
	}
}
