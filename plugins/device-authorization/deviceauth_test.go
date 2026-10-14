package deviceauth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	deviceauth "github.com/BladiCreator/go-modular-auth/plugins/device-authorization"
	"github.com/BladiCreator/go-modular-auth/plugins/device-authorization/plugins"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapter/memory"
	corecache "github.com/BladiCreator/go-modular-auth/cache/memory"
)

func setupTestAuth(t *testing.T) (*auth.Auth, plugins.DeviceAuthorization, *adaptermem.Adapter) {
	t.Helper()
	cAdapter := adaptermem.New()
	cCache := corecache.New()

	devModule := deviceauth.New(
		deviceauth.WithVerificationURI("https://auth.example.com/device"),
		deviceauth.WithExpiresIn(10*time.Minute),
		deviceauth.WithPollingInterval(1*time.Second),
	)

	a, err := auth.New(auth.Config{
		Adapter: cAdapter,
		Cache:   cCache,
		Plugins: []auth.PluginModule{devModule},
	})
	if err != nil {
		t.Fatalf("auth.New failed: %v", err)
	}

	devCap, err := auth.Get[plugins.DeviceAuthorization](a)
	if err != nil {
		t.Fatalf("auth.Get[plugins.DeviceAuthorization] failed: %v", err)
	}

	return a, devCap, cAdapter
}

func TestDeviceAuthorization_EndToEnd_Approval(t *testing.T) {
	ctx := context.Background()
	a, devAuth, _ := setupTestAuth(t)

	// Create test user
	userRes, err := a.SignUp(ctx, auth.SignUpInput{
		Email:    "tvuser@example.com",
		Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("SignUp failed: %v", err)
	}
	userPrincipal := userRes.Principal()

	// 1. Device initiates authorization
	startResp, err := devAuth.Start(ctx, deviceauth.DeviceAuthorizationRequestInput{
		ClientID: "smart_tv_app",
		Scope:    "read_media write_playlists",
	})
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	if startResp.DeviceCode == "" || startResp.UserCode == "" {
		t.Fatalf("expected device_code and user_code to be populated")
	}
	if startResp.VerificationURI != "https://auth.example.com/device" {
		t.Fatalf("unexpected verification URI: %s", startResp.VerificationURI)
	}

	// 2. Device polls while user has not approved -> authorization_pending
	_, err = devAuth.Poll(ctx, deviceauth.PollInput{
		DeviceCode: startResp.DeviceCode,
		ClientID:   "smart_tv_app",
	})
	if !errors.Is(err, deviceauth.ErrAuthorizationPending) {
		t.Fatalf("expected ErrAuthorizationPending, got %v", err)
	}

	// 3. User navigates to web page and enters user code
	verifyRes, err := devAuth.VerifyUserCode(ctx, deviceauth.VerifyUserCodeInput{
		UserCode: startResp.UserCode,
		ClientIP: "192.168.1.50",
	})
	if err != nil {
		t.Fatalf("VerifyUserCode failed: %v", err)
	}
	if verifyRes.ClientID != "smart_tv_app" {
		t.Fatalf("unexpected client id: %s", verifyRes.ClientID)
	}

	// Wait 1.1s so interval passes
	time.Sleep(1100 * time.Millisecond)

	// 4. User reviews and authorizes the request
	err = devAuth.Authorize(ctx, deviceauth.AuthorizeInput{
		UserCode:  startResp.UserCode,
		Principal: userPrincipal,
	})
	if err != nil {
		t.Fatalf("Authorize failed: %v", err)
	}

	// 5. Device polls again -> success & session issued!
	pollResp, err := devAuth.Poll(ctx, deviceauth.PollInput{
		DeviceCode: startResp.DeviceCode,
		ClientID:   "smart_tv_app",
	})
	if err != nil {
		t.Fatalf("Poll after authorization failed: %v", err)
	}
	if pollResp.Status != deviceauth.StatusConsumed {
		t.Fatalf("expected StatusConsumed, got %s", pollResp.Status)
	}
	if pollResp.UserID != userRes.User.ID {
		t.Fatalf("expected UserID %s, got %s", userRes.User.ID, pollResp.UserID)
	}
	if pollResp.Token == "" || pollResp.Session == nil {
		t.Fatalf("expected non-empty session and token")
	}

	// 6. Device polls again -> ErrInvalidGrant (single-use semantics enforced, replay prevented!)
	_, err = devAuth.Poll(ctx, deviceauth.PollInput{
		DeviceCode: startResp.DeviceCode,
		ClientID:   "smart_tv_app",
	})
	if !errors.Is(err, deviceauth.ErrInvalidGrant) {
		t.Fatalf("expected ErrInvalidGrant on replay poll, got %v", err)
	}
}

func TestDeviceAuthorization_Denial(t *testing.T) {
	ctx := context.Background()
	a, devAuth, _ := setupTestAuth(t)

	userRes, _ := a.SignUp(ctx, auth.SignUpInput{
		Email:    "denyuser@example.com",
		Password: "Password123!",
	})
	userPrincipal := userRes.Principal()

	startResp, err := devAuth.Start(ctx, deviceauth.DeviceAuthorizationRequestInput{
		ClientID: "smart_speaker",
	})
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// User rejects request
	err = devAuth.Deny(ctx, deviceauth.DenyInput{
		UserCode:  startResp.UserCode,
		Principal: userPrincipal,
	})
	if err != nil {
		t.Fatalf("Deny failed: %v", err)
	}

	// Wait 1.1s so interval passes
	time.Sleep(1100 * time.Millisecond)

	// Device polls -> access_denied
	_, err = devAuth.Poll(ctx, deviceauth.PollInput{
		DeviceCode: startResp.DeviceCode,
		ClientID:   "smart_speaker",
	})
	if !errors.Is(err, deviceauth.ErrAccessDenied) {
		t.Fatalf("expected ErrAccessDenied, got %v", err)
	}
}
