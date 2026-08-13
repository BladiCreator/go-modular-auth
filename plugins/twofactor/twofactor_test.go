package twofactor_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth/auth"
	"github.com/BladiCreator/go-modular-auth/config"
	"github.com/BladiCreator/go-modular-auth/internal/mock"
	"github.com/BladiCreator/go-modular-auth/plugins"
	"github.com/BladiCreator/go-modular-auth/plugins/twofactor"
)

func setupTwoFactorTest(t *testing.T, opts ...twofactor.Option) (*auth.Auth, *twofactor.Plugin, *mock.MockRepo) {
	t.Helper()
	repo := mock.NewMockRepo()

	app, err := auth.New(
		config.WithPlugins(
			plugins.TwoFactor(repo, opts...),
		),
	)
	if err != nil {
		t.Fatalf("Failed to initialize auth: %v", err)
	}

	p := auth.Plugin[twofactor.Plugin](app)
	return app, p, repo
}

func computeCurrentTOTP(t *testing.T, secret string, period int, digits int, alg twofactor.TOTPAlgorithm) string {
	t.Helper()
	code, err := twofactor.GenerateTOTPCode(secret, time.Now().Unix(), period, digits, alg)
	if err != nil {
		t.Fatalf("Failed to compute TOTP code: %v", err)
	}
	return code
}

func TestTwoFactor_EnableAndVerifyTOTP(t *testing.T) {
	_, p, repo := setupTwoFactorTest(t, twofactor.WithIssuer("TestApp"), twofactor.WithTOTPOptions(6, 30))
	ctx := context.Background()
	userID := "usr_test_123"

	// 1. Enable 2FA
	enableRes, err := p.Enable(ctx, twofactor.EnableParams{
		UserID: userID,
	})
	if err != nil {
		t.Fatalf("Enable 2FA failed: %v", err)
	}

	if !strings.Contains(enableRes.TOTPURI, "otpauth://totp/") {
		t.Errorf("Expected valid otpauth URI, got: %s", enableRes.TOTPURI)
	}
	if enableRes.Secret == "" {
		t.Error("Expected non-empty secret in EnableResult")
	}
	if len(enableRes.BackupCodes) != 10 {
		t.Errorf("Expected 10 backup codes, got %d", len(enableRes.BackupCodes))
	}

	// 2. Fetch stored record
	tf, err := repo.FindByUserID(ctx, userID)
	if err != nil {
		t.Fatalf("FindByUserID failed: %v", err)
	}
	if tf.Verified {
		t.Error("Expected 2FA to not be verified yet")
	}

	// 3. Verify with invalid code
	_, err = p.VerifyTOTP(ctx, twofactor.VerifyTOTPParams{
		UserID: userID,
		Code:   "000000",
	})
	if err != twofactor.ErrInvalidCode {
		t.Errorf("Expected ErrInvalidCode, got %v", err)
	}

	// 4. Verify with valid TOTP code
	validCode := computeCurrentTOTP(t, tf.Secret, 30, 6, twofactor.AlgorithmSHA1)
	res, err := p.VerifyTOTP(ctx, twofactor.VerifyTOTPParams{
		UserID: userID,
		Code:   validCode,
	})
	if err != nil || !res.Success {
		t.Fatalf("VerifyTOTP failed for valid code: %v", err)
	}
	if res.Method != twofactor.MethodTOTP {
		t.Errorf("Expected method %s, got %s", twofactor.MethodTOTP, res.Method)
	}

	// 5. Stored record should now be marked verified
	tfAfter, _ := repo.FindByUserID(ctx, userID)
	if !tfAfter.Verified {
		t.Error("Expected TwoFactor record to be verified after successful TOTP validation")
	}

	// 6. Test GetTOTPURI
	uri, err := p.GetTOTPURI(ctx, twofactor.GetTOTPURIParams{UserID: userID})
	if err != nil {
		t.Fatalf("GetTOTPURI failed: %v", err)
	}
	if !strings.Contains(uri, tf.Secret) {
		t.Errorf("Expected URI to contain secret %s, got: %s", tf.Secret, uri)
	}
}

func TestTwoFactor_BackupCodes(t *testing.T) {
	_, p, _ := setupTwoFactorTest(t, twofactor.WithBackupCodeOptions(5, 10))
	ctx := context.Background()
	userID := "usr_backup_test"

	enableRes, err := p.Enable(ctx, twofactor.EnableParams{UserID: userID})
	if err != nil {
		t.Fatalf("Enable failed: %v", err)
	}

	if len(enableRes.BackupCodes) != 5 {
		t.Fatalf("Expected 5 backup codes, got %d", len(enableRes.BackupCodes))
	}

	firstCode := enableRes.BackupCodes[0]

	// 1. Consume first backup code
	res, err := p.VerifyBackupCode(ctx, twofactor.VerifyBackupCodeParams{
		UserID: userID,
		Code:   firstCode,
	})
	if err != nil || !res.Success {
		t.Fatalf("VerifyBackupCode failed: %v", err)
	}
	if res.RemainingCodes != 4 {
		t.Errorf("Expected 4 remaining codes, got %d", res.RemainingCodes)
	}

	// 2. Re-using the same backup code must fail
	_, err = p.VerifyBackupCode(ctx, twofactor.VerifyBackupCodeParams{
		UserID: userID,
		Code:   firstCode,
	})
	if err != twofactor.ErrInvalidCode {
		t.Errorf("Expected ErrInvalidCode on second use, got: %v", err)
	}

	// 3. View remaining backup codes
	remainingRes, err := p.ViewBackupCodes(ctx, twofactor.ViewBackupCodesParams{UserID: userID})
	if err != nil {
		t.Fatalf("ViewBackupCodes failed: %v", err)
	}
	if len(remainingRes.BackupCodes) != 4 {
		t.Errorf("Expected 4 remaining codes, got %d", len(remainingRes.BackupCodes))
	}

	// 4. Regenerate backup codes
	newCodesRes, err := p.GenerateBackupCodes(ctx, twofactor.GenerateBackupCodesParams{UserID: userID})
	if err != nil {
		t.Fatalf("GenerateBackupCodes failed: %v", err)
	}
	if len(newCodesRes.BackupCodes) != 5 {
		t.Errorf("Expected 5 regenerated codes, got %d", len(newCodesRes.BackupCodes))
	}

	// Old remaining codes should now fail
	oldRemainingCode := remainingRes.BackupCodes[0]
	_, err = p.VerifyBackupCode(ctx, twofactor.VerifyBackupCodeParams{
		UserID: userID,
		Code:   oldRemainingCode,
	})
	if err != twofactor.ErrInvalidCode {
		t.Errorf("Expected old backup code to be invalidated after regeneration, got: %v", err)
	}
}

func TestTwoFactor_LockoutProtection(t *testing.T) {
	_, p, _ := setupTwoFactorTest(t, twofactor.WithLockoutProtection(3, 100*time.Millisecond))
	ctx := context.Background()
	userID := "usr_lockout_test"

	_, err := p.Enable(ctx, twofactor.EnableParams{UserID: userID})
	if err != nil {
		t.Fatalf("Enable failed: %v", err)
	}

	// 3 consecutive failed attempts
	for i := 0; i < 3; i++ {
		_, _ = p.VerifyTOTP(ctx, twofactor.VerifyTOTPParams{
			UserID: userID,
			Code:   "999999",
		})
	}

	// 4th attempt should result in lockout
	_, err = p.VerifyTOTP(ctx, twofactor.VerifyTOTPParams{
		UserID: userID,
		Code:   "999999",
	})
	if err != twofactor.ErrAccountLocked {
		t.Errorf("Expected ErrAccountLocked, got %v", err)
	}

	// Wait for lockout duration to expire
	time.Sleep(120 * time.Millisecond)

	// After expiry, verification should no longer report locked
	_, err = p.VerifyTOTP(ctx, twofactor.VerifyTOTPParams{
		UserID: userID,
		Code:   "999999",
	})
	if err != twofactor.ErrInvalidCode {
		t.Errorf("Expected ErrInvalidCode after lockout reset, got %v", err)
	}
}

func TestTwoFactor_ChallengeOTP(t *testing.T) {
	var dispatchedCode string
	var dispatchedUserID string

	_, p, _ := setupTwoFactorTest(t, twofactor.WithSendOTP(func(ctx context.Context, userID string, otp string) error {
		dispatchedUserID = userID
		dispatchedCode = otp
		return nil
	}))

	ctx := context.Background()
	userID := "usr_otp_test"

	// 1. Send OTP challenge
	otpRes, err := p.SendOTP(ctx, twofactor.SendOTPParams{UserID: userID})
	if err != nil {
		t.Fatalf("SendOTP failed: %v", err)
	}
	if otpRes.ExpiresAt.IsZero() {
		t.Error("Expected non-zero expiration timestamp")
	}

	if dispatchedUserID != userID {
		t.Errorf("Expected dispatched userID %s, got %s", userID, dispatchedUserID)
	}
	if len(dispatchedCode) != 6 {
		t.Errorf("Expected 6-digit OTP code, got %s", dispatchedCode)
	}

	// 2. Verify with wrong code
	_, err = p.VerifyOTP(ctx, twofactor.VerifyOTPParams{
		UserID: userID,
		Code:   "000000",
	})
	if err != twofactor.ErrInvalidCode {
		t.Errorf("Expected ErrInvalidCode, got %v", err)
	}

	// 3. Verify with correct code
	res, err := p.VerifyOTP(ctx, twofactor.VerifyOTPParams{
		UserID: userID,
		Code:   dispatchedCode,
	})
	if err != nil || !res.Success {
		t.Fatalf("VerifyOTP failed with correct code: %v", err)
	}

	// 4. Re-using the same OTP must fail
	_, err = p.VerifyOTP(ctx, twofactor.VerifyOTPParams{
		UserID: userID,
		Code:   dispatchedCode,
	})
	if err != twofactor.ErrOTPExpired {
		t.Errorf("Expected ErrOTPExpired on reuse, got %v", err)
	}
}

func TestTwoFactor_SignInChallengeFlow(t *testing.T) {
	_, p, repo := setupTwoFactorTest(t)
	ctx := context.Background()
	userID := "usr_challenge_test"

	_, err := p.Enable(ctx, twofactor.EnableParams{UserID: userID})
	if err != nil {
		t.Fatalf("Enable failed: %v", err)
	}

	tf, _ := repo.FindByUserID(ctx, userID)
	validTOTP := computeCurrentTOTP(t, tf.Secret, 30, 6, twofactor.AlgorithmSHA1)

	// 1. Create Challenge
	challenge, err := p.CreateChallenge(ctx, twofactor.CreateChallengeParams{UserID: userID})
	if err != nil {
		t.Fatalf("CreateChallenge failed: %v", err)
	}
	if challenge.ChallengeToken == "" {
		t.Fatal("Expected valid ChallengeToken")
	}

	// 2. Verify Challenge with TOTP
	res, err := p.VerifyChallenge(ctx, twofactor.VerifyChallengeParams{
		ChallengeToken: challenge.ChallengeToken,
		Method:         twofactor.MethodTOTP,
		Code:           validTOTP,
	})
	if err != nil || !res.Success {
		t.Fatalf("VerifyChallenge failed: %v", err)
	}

	// 3. Challenge token is single-use, subsequent verification must fail
	_, err = p.VerifyChallenge(ctx, twofactor.VerifyChallengeParams{
		ChallengeToken: challenge.ChallengeToken,
		Method:         twofactor.MethodTOTP,
		Code:           validTOTP,
	})
	if err != twofactor.ErrInvalidChallengeToken {
		t.Errorf("Expected ErrInvalidChallengeToken on reuse, got %v", err)
	}
}

func TestTwoFactor_TrustedDevices(t *testing.T) {
	deviceSecret := "test-hmac-secret-for-devices-12345"
	_, p, repo := setupTwoFactorTest(t,
		twofactor.WithTrustDevice(deviceSecret, 24*time.Hour),
	)
	ctx := context.Background()
	userID := "usr_device_test"
	deviceID := "dev_pixel_8_pro"

	_, err := p.Enable(ctx, twofactor.EnableParams{UserID: userID})
	if err != nil {
		t.Fatalf("Enable failed: %v", err)
	}

	tf, _ := repo.FindByUserID(ctx, userID)
	validTOTP := computeCurrentTOTP(t, tf.Secret, 30, 6, twofactor.AlgorithmSHA1)

	// 1. Verify TOTP requesting TrustDevice
	res, err := p.VerifyTOTP(ctx, twofactor.VerifyTOTPParams{
		UserID:      userID,
		Code:        validTOTP,
		TrustDevice: true,
		DeviceID:    deviceID,
	})
	if err != nil {
		t.Fatalf("VerifyTOTP failed: %v", err)
	}
	if res.TrustDeviceToken == "" {
		t.Fatal("Expected non-empty TrustDeviceToken in VerifyResult")
	}

	// 2. Verify trust on device
	isTrusted, err := p.VerifyTrustDevice(ctx, twofactor.VerifyTrustDeviceParams{
		UserID:   userID,
		DeviceID: deviceID,
		Token:    res.TrustDeviceToken,
	})
	if err != nil || !isTrusted {
		t.Errorf("Expected device to be trusted, got trusted=%t, err=%v", isTrusted, err)
	}

	// 3. Verify with wrong token fails
	isTrusted, _ = p.VerifyTrustDevice(ctx, twofactor.VerifyTrustDeviceParams{
		UserID:   userID,
		DeviceID: deviceID,
		Token:    "tampered-device-token",
	})
	if isTrusted {
		t.Error("Expected tampered token to fail device trust verification")
	}

	// 4. Revoke single device
	if err := p.RevokeTrustedDevice(ctx, twofactor.RevokeTrustedDeviceParams{UserID: userID, DeviceID: deviceID}); err != nil {
		t.Fatalf("RevokeTrustedDevice failed: %v", err)
	}
	isTrusted, _ = p.VerifyTrustDevice(ctx, twofactor.VerifyTrustDeviceParams{
		UserID:   userID,
		DeviceID: deviceID,
		Token:    res.TrustDeviceToken,
	})
	if isTrusted {
		t.Error("Expected device to no longer be trusted after revocation")
	}
}

func TestTwoFactor_Disable(t *testing.T) {
	_, p, repo := setupTwoFactorTest(t)
	ctx := context.Background()
	userID := "usr_disable_test"

	_, err := p.Enable(ctx, twofactor.EnableParams{UserID: userID})
	if err != nil {
		t.Fatalf("Enable failed: %v", err)
	}

	// Disable
	if err := p.Disable(ctx, twofactor.DisableParams{UserID: userID}); err != nil {
		t.Fatalf("Disable failed: %v", err)
	}

	// Stored record should be gone
	_, err = repo.FindByUserID(ctx, userID)
	if err != twofactor.ErrTwoFactorNotEnabled {
		t.Errorf("Expected ErrTwoFactorNotEnabled after disable, got %v", err)
	}
}

func TestTwoFactor_EventEmissions(t *testing.T) {
	app, p, repo := setupTwoFactorTest(t, twofactor.WithSendOTP(func(ctx context.Context, userID string, otp string) error {
		return nil
	}))
	ctx := context.Background()
	userID := "usr_events_test"

	var enableBeforeEmitted, enableAfterEmitted, totpGeneratedEmitted bool
	var verifySuccessEmitted, verifyFailedEmitted, sendOTPBeforeEmitted, sendOTPAfterEmitted bool
	var challengeCreatedEmitted, disableBeforeEmitted, disableAfterEmitted bool

	app.Events().Subscribe(twofactor.EventEnableBefore, func(ctx context.Context, payload any) {
		if req, ok := payload.(*twofactor.EnableBeforeEventPayload); ok && req.UserID == userID {
			enableBeforeEmitted = true
		}
	})

	app.Events().Subscribe(twofactor.EventEnableAfter, func(ctx context.Context, payload any) {
		if req, ok := payload.(*twofactor.EnableAfterEventPayload); ok && req.UserID == userID {
			enableAfterEmitted = true
		}
	})

	app.Events().Subscribe(twofactor.EventTOTPGenerated, func(ctx context.Context, payload any) {
		if req, ok := payload.(*twofactor.TOTPGeneratedEventPayload); ok && req.UserID == userID {
			totpGeneratedEmitted = true
		}
	})

	app.Events().Subscribe(twofactor.EventVerifyFailed, func(ctx context.Context, payload any) {
		if req, ok := payload.(*twofactor.VerifyFailedEventPayload); ok && req.UserID == userID {
			verifyFailedEmitted = true
		}
	})

	app.Events().Subscribe(twofactor.EventVerifySuccess, func(ctx context.Context, payload any) {
		if req, ok := payload.(*twofactor.VerifySuccessEventPayload); ok && req.UserID == userID {
			verifySuccessEmitted = true
		}
	})

	app.Events().Subscribe(twofactor.EventSendOTPBefore, func(ctx context.Context, payload any) {
		if req, ok := payload.(*twofactor.SendOTPBeforeEventPayload); ok && req.UserID == userID {
			sendOTPBeforeEmitted = true
		}
	})

	app.Events().Subscribe(twofactor.EventSendOTPAfter, func(ctx context.Context, payload any) {
		if req, ok := payload.(*twofactor.SendOTPAfterEventPayload); ok && req.UserID == userID {
			sendOTPAfterEmitted = true
		}
	})

	app.Events().Subscribe(twofactor.EventChallengeCreated, func(ctx context.Context, payload any) {
		if req, ok := payload.(*twofactor.ChallengeCreatedEventPayload); ok && req.UserID == userID {
			challengeCreatedEmitted = true
		}
	})

	app.Events().Subscribe(twofactor.EventDisableBefore, func(ctx context.Context, payload any) {
		if req, ok := payload.(*twofactor.DisableBeforeEventPayload); ok && req.UserID == userID {
			disableBeforeEmitted = true
		}
	})

	app.Events().Subscribe(twofactor.EventDisableAfter, func(ctx context.Context, payload any) {
		if req, ok := payload.(*twofactor.DisableAfterEventPayload); ok && req.UserID == userID {
			disableAfterEmitted = true
		}
	})

	// 1. Enable
	_, err := p.Enable(ctx, twofactor.EnableParams{UserID: userID})
	if err != nil {
		t.Fatalf("Enable failed: %v", err)
	}

	// 2. Failed Verify
	_, _ = p.VerifyTOTP(ctx, twofactor.VerifyTOTPParams{UserID: userID, Code: "000000"})

	// 3. Successful Verify
	tf, _ := repo.FindByUserID(ctx, userID)
	validCode := computeCurrentTOTP(t, tf.Secret, 30, 6, twofactor.AlgorithmSHA1)
	_, _ = p.VerifyTOTP(ctx, twofactor.VerifyTOTPParams{UserID: userID, Code: validCode})

	// 4. Send OTP
	_, _ = p.SendOTP(ctx, twofactor.SendOTPParams{UserID: userID})

	// 5. Create Challenge
	_, _ = p.CreateChallenge(ctx, twofactor.CreateChallengeParams{UserID: userID})

	// 6. Disable
	_ = p.Disable(ctx, twofactor.DisableParams{UserID: userID})

	if !enableBeforeEmitted {
		t.Error("Expected EventEnableBefore to be emitted")
	}
	if !enableAfterEmitted {
		t.Error("Expected EventEnableAfter to be emitted")
	}
	if !totpGeneratedEmitted {
		t.Error("Expected EventTOTPGenerated to be emitted")
	}
	if !verifyFailedEmitted {
		t.Error("Expected EventVerifyFailed to be emitted")
	}
	if !verifySuccessEmitted {
		t.Error("Expected EventVerifySuccess to be emitted")
	}
	if !sendOTPBeforeEmitted {
		t.Error("Expected EventSendOTPBefore to be emitted")
	}
	if !sendOTPAfterEmitted {
		t.Error("Expected EventSendOTPAfter to be emitted")
	}
	if !challengeCreatedEmitted {
		t.Error("Expected EventChallengeCreated to be emitted")
	}
	if !disableBeforeEmitted {
		t.Error("Expected EventDisableBefore to be emitted")
	}
	if !disableAfterEmitted {
		t.Error("Expected EventDisableAfter to be emitted")
	}
}

func TestTwoFactor_ExtraMetadataAndContextKeys(t *testing.T) {
	app, p, _ := setupTwoFactorTest(t)
	ctx := context.Background()
	userID := "usr_extra_789"

	var interceptedMethod string
	var extraCaptured bool

	app.Events().Subscribe(twofactor.EventEnableBefore, func(ctx context.Context, payload any) {
		if req, ok := payload.(*twofactor.EnableBeforeEventPayload); ok && req.Params != nil {
			req.Params.Set(twofactor.ExtraKeyTwoFactorMethod, twofactor.MethodTOTP)
			if m, ok := req.Params.Get(twofactor.ExtraKeyTwoFactorMethod); ok {
				interceptedMethod, _ = m.(string)
				extraCaptured = true
			}
		}
	})

	_, err := p.Enable(ctx, twofactor.EnableParams{UserID: userID})
	if err != nil {
		t.Fatalf("Enable failed: %v", err)
	}

	if !extraCaptured || interceptedMethod != twofactor.MethodTOTP {
		t.Errorf("Expected ExtraKeyTwoFactorMethod to be captured, got %s", interceptedMethod)
	}

	// Verify Context helper functions
	if k := twofactor.TwoFactorPendingKey(userID); k != twofactor.ContextKeyTwoFactorPendingPrefix+userID {
		t.Errorf("Unexpected TwoFactorPendingKey: %s", k)
	}
	if k := twofactor.TwoFactorVerifiedKey(userID); k != twofactor.ContextKeyTwoFactorVerifiedPrefix+userID {
		t.Errorf("Unexpected TwoFactorVerifiedKey: %s", k)
	}
	if k := twofactor.TwoFactorMethodKey(userID); k != twofactor.ContextKeyTwoFactorMethodPrefix+userID {
		t.Errorf("Unexpected TwoFactorMethodKey: %s", k)
	}
	if k := twofactor.TwoFactorChallengeKey("tok123"); k != twofactor.ContextKeyTwoFactorChallengePrefix+"tok123" {
		t.Errorf("Unexpected TwoFactorChallengeKey: %s", k)
	}
}
