package twofactor_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth/adapters/memory"
	"github.com/BladiCreator/go-modular-auth/auth"
	"github.com/BladiCreator/go-modular-auth/config"
	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/plugins"
	"github.com/BladiCreator/go-modular-auth/plugins/emailpassword"
	"github.com/BladiCreator/go-modular-auth/plugins/twofactor"
)

func TestTwoFactor_MFAChallenge_CompleteFlow(t *testing.T) {
	ctx := context.Background()
	store := memory.New()

	app, err := auth.New(
		config.WithSessionRepository(store),
		config.WithSessionConfig(auth.SessionConfig{
			DefaultDuration: 24 * time.Hour,
		}),
		config.WithPlugins(
			plugins.EmailPassword(store),
			plugins.TwoFactor(store,
				twofactor.WithChallengeExpiry(5*time.Minute),
				twofactor.WithTrustDevice("test-device-secret-key-12345", 30*24*time.Hour),
			),
		),
	)
	if err != nil {
		t.Fatalf("Failed to initialize Auth engine: %v", err)
	}

	epPlugin := auth.Plugin[emailpassword.Plugin](app)
	tfPlugin := auth.Plugin[twofactor.Plugin](app)

	// 1. Sign up user
	user, err := epPlugin.SignUp(ctx, dto.SignUpParams{
		Email:    "mfa.user@example.com",
		Password: "SecurePassword123!",
		Name:     "MFA User",
	})
	if err != nil {
		t.Fatalf("SignUp failed: %v", err)
	}

	// 2. Sign in before 2FA is enrolled -> Should emit session directly without challenge
	initialAuthRes, err := epPlugin.SignIn(ctx, dto.SignInParams{
		Email:    "mfa.user@example.com",
		Password: "SecurePassword123!",
	})
	if err != nil {
		t.Fatalf("Initial SignIn failed: %v", err)
	}
	if !initialAuthRes.IsComplete() {
		t.Fatalf("Expected IsComplete() to be true for user without 2FA")
	}
	if initialAuthRes.RequiresChallenge() {
		t.Fatalf("Expected RequiresChallenge() to be false for user without 2FA")
	}
	if initialAuthRes.SessionData() == nil || initialAuthRes.Session.Token == "" {
		t.Fatalf("Expected valid SessionData")
	}

	// 3. Enroll in 2FA
	enableRes, err := tfPlugin.Enable(ctx, twofactor.EnableParams{
		UserID: user.ID,
	})
	if err != nil {
		t.Fatalf("Enable 2FA failed: %v", err)
	}

	// Compute current TOTP code to verify enrollment
	totpCode, err := twofactor.GenerateTOTPCode(enableRes.Secret, time.Now().Unix(), 30, 6, twofactor.AlgorithmSHA1)
	if err != nil {
		t.Fatalf("Failed to compute TOTP code: %v", err)
	}

	// Verify TOTP to activate 2FA
	vRes, err := tfPlugin.VerifyTOTP(ctx, twofactor.VerifyTOTPParams{
		UserID: user.ID,
		Code:   totpCode,
	})
	if err != nil || !vRes.Success {
		t.Fatalf("VerifyTOTP failed to activate 2FA: %v", err)
	}

	// 4. Sign in with 2FA active -> Must return pending MFA challenge instead of session!
	mfaAuthRes, err := epPlugin.SignIn(ctx, dto.SignInParams{
		Email:    "mfa.user@example.com",
		Password: "SecurePassword123!",
	})
	if err != nil {
		t.Fatalf("MFA SignIn failed: %v", err)
	}
	if mfaAuthRes.IsComplete() {
		t.Fatalf("Expected IsComplete() to be false when 2FA is active")
	}
	if !mfaAuthRes.RequiresChallenge() {
		t.Fatalf("Expected RequiresChallenge() to be true when 2FA is active")
	}
	if mfaAuthRes.SessionData() != nil {
		t.Fatalf("Expected SessionData() to be nil during challenge phase")
	}

	challenge := mfaAuthRes.Challenge()
	if challenge == nil || challenge.TempToken == "" {
		t.Fatalf("Expected valid challenge with TempToken")
	}
	if challenge.UserID != user.ID {
		t.Errorf("Expected challenge UserID %s, got %s", user.ID, challenge.UserID)
	}
	if challenge.FactorRequired != "totp" {
		t.Errorf("Expected FactorRequired 'totp', got %s", challenge.FactorRequired)
	}

	// 5. Anti-Tampering Test: altered challenge token should be rejected
	tamperedToken := challenge.TempToken + "tampered"
	_, err = app.VerifyTwoFactorChallenge(ctx, tamperedToken, totpCode)
	if err == nil {
		t.Fatalf("Expected error when verifying tampered challenge token")
	}

	// 6. Wrong TOTP code should fail, without revoking challenge
	_, err = app.VerifyTwoFactorChallenge(ctx, challenge.TempToken, "000000")
	if !errors.Is(err, twofactor.ErrInvalidCode) {
		t.Fatalf("Expected ErrInvalidCode for wrong code, got %v", err)
	}

	// 7. Successful challenge resolution via auth.VerifyTwoFactorChallenge
	finalSessionData, err := app.VerifyTwoFactorChallenge(ctx, challenge.TempToken, totpCode,
		auth.WithIPAddress("192.168.1.100"),
		auth.WithUserAgent("Antigravity-MFA-Client/1.0"),
	)
	if err != nil {
		t.Fatalf("VerifyTwoFactorChallenge failed: %v", err)
	}
	if finalSessionData == nil || finalSessionData.Session == nil {
		t.Fatalf("Expected non-nil SessionData upon challenge resolution")
	}
	if finalSessionData.Session.Token == "" {
		t.Fatalf("Expected non-empty session token")
	}
	if finalSessionData.Session.IPAddress != "192.168.1.100" {
		t.Errorf("Expected session IP 192.168.1.100, got %s", finalSessionData.Session.IPAddress)
	}

	// 8. Replay Attack Prevention: Attempting to resolve the same challenge token again must fail
	_, err = app.VerifyTwoFactorChallenge(ctx, challenge.TempToken, totpCode)
	if !errors.Is(err, twofactor.ErrInvalidChallengeToken) && !errors.Is(err, auth.ErrInvalidChallengeToken) {
		t.Fatalf("Expected challenge to be revoked after single use, got %v", err)
	}

	// 9. Resolving challenge using a single-use Backup Code
	backupSignInRes, err := epPlugin.SignIn(ctx, dto.SignInParams{
		Email:    "mfa.user@example.com",
		Password: "SecurePassword123!",
	})
	if err != nil || !backupSignInRes.RequiresChallenge() {
		t.Fatalf("Expected MFA challenge for backup code test: %v", err)
	}

	backupCode := enableRes.BackupCodes[0]
	backupSessionData, err := app.VerifyChallenge(ctx, dto.VerifyChallengeParams{
		ChallengeToken: backupSignInRes.Challenge().TempToken,
		Code:           backupCode,
		Method:         "backup_code",
	})
	if err != nil {
		t.Fatalf("VerifyChallenge with backup code failed: %v", err)
	}
	if backupSessionData.Session == nil || backupSessionData.Session.Token == "" {
		t.Fatalf("Expected session created via backup code verification")
	}

	// 10. Trusted Device Bypass Flow
	// Client signs in, solves challenge with TrustDevice=true
	deviceSignInRes, err := epPlugin.SignIn(ctx, dto.SignInParams{
		Email:    "mfa.user@example.com",
		Password: "SecurePassword123!",
	})
	if err != nil || !deviceSignInRes.RequiresChallenge() {
		t.Fatalf("Expected challenge: %v", err)
	}

	deviceID := "client-macbook-pro-id"
	deviceSessionData, err := app.VerifyChallenge(ctx, dto.VerifyChallengeParams{
		ChallengeToken: deviceSignInRes.Challenge().TempToken,
		Code:           totpCode,
		TrustDevice:    true,
		DeviceID:       deviceID,
	})
	if err != nil {
		t.Fatalf("VerifyChallenge with TrustDevice failed: %v", err)
	}
	if deviceSessionData.Session == nil {
		t.Fatalf("Expected session created")
	}

	// Check that a trusted device token was registered
	trustedRec, err := store.FindTrustDevice(ctx, user.ID, deviceID)
	if err != nil || trustedRec == nil {
		t.Fatalf("Expected trusted device record in store: %v", err)
	}

	// Now client signs in providing device_id and trust_device_token in Extra -> Should bypass 2FA!
	bypassRes, err := epPlugin.SignIn(ctx, dto.SignInParams{
		Email:    "mfa.user@example.com",
		Password: "SecurePassword123!",
	}, auth.WithExtra("device_id", deviceID), auth.WithExtra("trust_device_token", trustedRec.TokenHash))
	if err != nil {
		t.Fatalf("SignIn with trusted device bypass failed: %v", err)
	}
	if !bypassRes.IsComplete() {
		t.Fatalf("Expected 2FA to be bypassed for trusted device, got requiresChallenge=%v", bypassRes.RequiresChallenge())
	}
	if bypassRes.Session == nil || bypassRes.Session.Token == "" {
		t.Fatalf("Expected immediate session emission for trusted device")
	}
}

func TestTwoFactor_MFAChallenge_ExpiredChallenge(t *testing.T) {
	ctx := context.Background()
	store := memory.New()

	app, err := auth.New(
		config.WithSessionRepository(store),
		config.WithPlugins(
			plugins.EmailPassword(store),
			plugins.TwoFactor(store,
				twofactor.WithChallengeExpiry(10*time.Millisecond), // Very short TTL
			),
		),
	)
	if err != nil {
		t.Fatalf("Failed to initialize Auth engine: %v", err)
	}

	epPlugin := auth.Plugin[emailpassword.Plugin](app)
	tfPlugin := auth.Plugin[twofactor.Plugin](app)

	user, _ := epPlugin.SignUp(ctx, dto.SignUpParams{
		Email:    "expired.mfa@example.com",
		Password: "SecurePassword123!",
		Name:     "Expired MFA User",
	})

	enableRes, _ := tfPlugin.Enable(ctx, twofactor.EnableParams{UserID: user.ID})
	totpCode, _ := twofactor.GenerateTOTPCode(enableRes.Secret, time.Now().Unix(), 30, 6, twofactor.AlgorithmSHA1)
	_, _ = tfPlugin.VerifyTOTP(ctx, twofactor.VerifyTOTPParams{UserID: user.ID, Code: totpCode})

	res, err := epPlugin.SignIn(ctx, dto.SignInParams{
		Email:    "expired.mfa@example.com",
		Password: "SecurePassword123!",
	})
	if err != nil || !res.RequiresChallenge() {
		t.Fatalf("Expected challenge requirement")
	}

	// Wait for challenge to expire
	time.Sleep(25 * time.Millisecond)

	_, err = app.VerifyTwoFactorChallenge(ctx, res.Challenge().TempToken, totpCode)
	if !errors.Is(err, twofactor.ErrChallengeExpired) && !errors.Is(err, auth.ErrChallengeExpired) {
		t.Fatalf("Expected ErrChallengeExpired for timed out challenge, got %v", err)
	}
}
