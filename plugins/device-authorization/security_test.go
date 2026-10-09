package deviceauth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	deviceauth "github.com/BladiCreator/go-modular-auth-device-authorization"
	"github.com/BladiCreator/go-modular-auth-device-authorization/plugins"
	devicememory "github.com/BladiCreator/go-modular-auth-device-authorization/store/memory"
	corecache "github.com/BladiCreator/go-modular-auth/cache/memory"
	corememory "github.com/BladiCreator/go-modular-auth/store/memory"
)

func TestDeviceAuth_Security_SlowDown(t *testing.T) {
	ctx := context.Background()
	_, devAuth, _ := setupTestAuth(t)

	startResp, err := devAuth.Start(ctx, deviceauth.DeviceAuthorizationRequestInput{
		ClientID: "fast_polling_device",
	})
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// First poll records LastPolledAt -> returns ErrAuthorizationPending
	_, err = devAuth.Poll(ctx, deviceauth.PollInput{
		DeviceCode: startResp.DeviceCode,
		ClientID:   "fast_polling_device",
	})
	if !errors.Is(err, deviceauth.ErrAuthorizationPending) {
		t.Fatalf("expected ErrAuthorizationPending on first poll, got %v", err)
	}

	// Immediate second poll (< 1 second) must trigger ErrSlowDown!
	_, err = devAuth.Poll(ctx, deviceauth.PollInput{
		DeviceCode: startResp.DeviceCode,
		ClientID:   "fast_polling_device",
	})
	if !errors.Is(err, deviceauth.ErrSlowDown) {
		t.Fatalf("expected ErrSlowDown on immediate poll, got %v", err)
	}
}

func TestDeviceAuth_Security_Expiration(t *testing.T) {
	ctx := context.Background()
	cStore := corememory.New()
	cCache := corecache.New()
	devStore := devicememory.New()

	devModule := deviceauth.New(
		deviceauth.WithStore(devStore),
		deviceauth.WithExpiresIn(50*time.Millisecond), // Short TTL for testing
	)

	a, err := auth.New(auth.Config{
		Store:   cStore,
		Cache:   cCache,
		Plugins: []auth.PluginModule{devModule},
	})
	if err != nil {
		t.Fatalf("auth.New failed: %v", err)
	}

	devAuth, _ := auth.Get[plugins.DeviceAuthorization](a)

	startResp, err := devAuth.Start(ctx, deviceauth.DeviceAuthorizationRequestInput{
		ClientID: "expiring_device",
	})
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Wait for TTL expiration
	time.Sleep(100 * time.Millisecond)

	// Polling must return ErrExpiredToken
	_, err = devAuth.Poll(ctx, deviceauth.PollInput{
		DeviceCode: startResp.DeviceCode,
		ClientID:   "expiring_device",
	})
	if !errors.Is(err, deviceauth.ErrExpiredToken) {
		t.Fatalf("expected ErrExpiredToken, got %v", err)
	}

	// User code verification must return ErrExpiredToken
	_, err = devAuth.VerifyUserCode(ctx, deviceauth.VerifyUserCodeInput{
		UserCode: startResp.UserCode,
	})
	if !errors.Is(err, deviceauth.ErrExpiredToken) {
		t.Fatalf("expected ErrExpiredToken on VerifyUserCode, got %v", err)
	}
}

func TestDeviceAuth_Security_ClientBinding(t *testing.T) {
	ctx := context.Background()
	_, devAuth, _ := setupTestAuth(t)

	startResp, err := devAuth.Start(ctx, deviceauth.DeviceAuthorizationRequestInput{
		ClientID: "legitimate_client",
	})
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Mismatched client ID must fail
	_, err = devAuth.Poll(ctx, deviceauth.PollInput{
		DeviceCode: startResp.DeviceCode,
		ClientID:   "impersonator_client",
	})
	if !errors.Is(err, deviceauth.ErrInvalidGrant) {
		t.Fatalf("expected ErrInvalidGrant for client_id mismatch, got %v", err)
	}
}

func TestDeviceAuth_Security_BruteForceProtection(t *testing.T) {
	ctx := context.Background()
	cStore := corememory.New()
	cCache := corecache.New()
	devStore := devicememory.New()

	devModule := deviceauth.New(
		deviceauth.WithStore(devStore),
		deviceauth.WithMaxFailedAttempts(3),
		deviceauth.WithRateLimit(5),
	)

	a, err := auth.New(auth.Config{
		Store:   cStore,
		Cache:   cCache,
		Plugins: []auth.PluginModule{devModule},
	})
	if err != nil {
		t.Fatalf("auth.New failed: %v", err)
	}

	devAuth, _ := auth.Get[plugins.DeviceAuthorization](a)

	startResp, err := devAuth.Start(ctx, deviceauth.DeviceAuthorizationRequestInput{
		ClientID: "target_client",
	})
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Simulate 3 failed attempts on store for that code
	_, _ = devStore.IncrementFailedAttempts(ctx, startResp.UserCode)
	_, _ = devStore.IncrementFailedAttempts(ctx, startResp.UserCode)
	_, _ = devStore.IncrementFailedAttempts(ctx, startResp.UserCode)

	// Now verification must be locked with ErrMaxAttemptsExceeded
	_, err = devAuth.VerifyUserCode(ctx, deviceauth.VerifyUserCodeInput{
		UserCode: startResp.UserCode,
	})
	if !errors.Is(err, deviceauth.ErrMaxAttemptsExceeded) {
		t.Fatalf("expected ErrMaxAttemptsExceeded, got %v", err)
	}
}

func TestDeviceAuth_Security_AuditEvents(t *testing.T) {
	ctx := context.Background()
	cStore := corememory.New()
	cCache := corecache.New()
	devStore := devicememory.New()

	var eventsEmitted []auth.Event

	devModule := deviceauth.New(
		deviceauth.WithStore(devStore),
	)

	a, err := auth.New(auth.Config{
		Store:   cStore,
		Cache:   cCache,
		Plugins: []auth.PluginModule{devModule},
	})
	if err != nil {
		t.Fatalf("auth.New failed: %v", err)
	}

	a.Events().SubscribeAll(func(ctx context.Context, e auth.Event) {
		eventsEmitted = append(eventsEmitted, e)
	})

	devAuth, _ := auth.Get[plugins.DeviceAuthorization](a)

	userRes, _ := a.SignUp(ctx, auth.SignUpInput{Email: "audit@example.com", Password: "Password123!"})

	startResp, _ := devAuth.Start(ctx, deviceauth.DeviceAuthorizationRequestInput{
		ClientID: "audit_client",
	})

	_ = devAuth.Authorize(ctx, deviceauth.AuthorizeInput{
		UserCode:  startResp.UserCode,
		Principal: userRes.Principal(),
	})

	var foundStarted, foundAuthorized bool
	for _, e := range eventsEmitted {
		if e.Name == deviceauth.EventDeviceAuthStarted {
			foundStarted = true
		}
		if e.Name == deviceauth.EventDeviceAuthAuthorized {
			foundAuthorized = true
		}
	}

	if !foundStarted {
		t.Fatalf("expected EventDeviceAuthStarted to be emitted")
	}
	if !foundAuthorized {
		t.Fatalf("expected EventDeviceAuthAuthorized to be emitted")
	}
}
