package twofactor_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
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

// computeCurrentTOTP computes the expected 6-digit TOTP code for testing
func computeCurrentTOTP(t *testing.T, secret string, period int, digits int) string {
	t.Helper()
	secretBytes, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		t.Fatalf("Failed to decode base32 secret: %v", err)
	}

	counter := uint64(time.Now().Unix() / int64(period))
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	mac := hmac.New(sha1.New, secretBytes)
	mac.Write(buf)
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0xf
	binCode := (int32(sum[offset]&0x7f) << 24) |
		(int32(sum[offset+1]&0xff) << 16) |
		(int32(sum[offset+2]&0xff) << 8) |
		(int32(sum[offset+3] & 0xff))

	mod := int32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, binCode%mod)
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
	if len(enableRes.BackupCodes) != 10 {
		t.Errorf("Expected 10 backup codes, got %d", len(enableRes.BackupCodes))
	}

	// 2. Fetch stored record
	tf, err := repo.FindByUserID(ctx, userID)
	if err != nil {
		t.Fatalf("FindByUserID failed: %v", err)
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
	validCode := computeCurrentTOTP(t, tf.Secret, 30, 6)
	ok, err := p.VerifyTOTP(ctx, twofactor.VerifyTOTPParams{
		UserID: userID,
		Code:   validCode,
	})
	if err != nil || !ok {
		t.Fatalf("VerifyTOTP failed for valid code: %v", err)
	}

	// 5. Test GetTOTPURI
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
	valid, err := p.VerifyBackupCode(ctx, twofactor.VerifyBackupCodeParams{
		UserID: userID,
		Code:   firstCode,
	})
	if err != nil || !valid {
		t.Fatalf("VerifyBackupCode failed: %v", err)
	}

	// 2. Re-using the same backup code must fail
	valid, err = p.VerifyBackupCode(ctx, twofactor.VerifyBackupCodeParams{
		UserID: userID,
		Code:   firstCode,
	})
	if err != twofactor.ErrInvalidCode || valid {
		t.Errorf("Expected ErrInvalidCode on second use, got: %v", err)
	}

	// 3. View remaining backup codes
	remaining, err := p.ViewBackupCodes(ctx, twofactor.ViewBackupCodesParams{UserID: userID})
	if err != nil {
		t.Fatalf("ViewBackupCodes failed: %v", err)
	}
	if len(remaining) != 4 {
		t.Errorf("Expected 4 remaining codes, got %d", len(remaining))
	}

	// 4. Regenerate backup codes
	newCodes, err := p.GenerateBackupCodes(ctx, twofactor.GenerateBackupCodesParams{UserID: userID})
	if err != nil {
		t.Fatalf("GenerateBackupCodes failed: %v", err)
	}
	if len(newCodes) != 5 {
		t.Errorf("Expected 5 regenerated codes, got %d", len(newCodes))
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
	err := p.SendOTP(ctx, twofactor.SendOTPParams{UserID: userID})
	if err != nil {
		t.Fatalf("SendOTP failed: %v", err)
	}

	if dispatchedUserID != userID {
		t.Errorf("Expected dispatched userID %s, got %s", userID, dispatchedUserID)
	}
	if len(dispatchedCode) != 6 {
		t.Errorf("Expected 6-digit OTP code, got %s", dispatchedCode)
	}

	// 2. Verify with wrong code
	valid, err := p.VerifyOTP(ctx, twofactor.VerifyOTPParams{
		UserID: userID,
		Code:   "000000",
	})
	if err != twofactor.ErrInvalidCode || valid {
		t.Errorf("Expected ErrInvalidCode, got %v", err)
	}

	// 3. Verify with correct code
	valid, err = p.VerifyOTP(ctx, twofactor.VerifyOTPParams{
		UserID: userID,
		Code:   dispatchedCode,
	})
	if err != nil || !valid {
		t.Fatalf("VerifyOTP failed with correct code: %v", err)
	}

	// 4. Re-using the same OTP must fail
	valid, err = p.VerifyOTP(ctx, twofactor.VerifyOTPParams{
		UserID: userID,
		Code:   dispatchedCode,
	})
	if err != twofactor.ErrOTPExpired || valid {
		t.Errorf("Expected ErrOTPExpired on reuse, got %v", err)
	}
}

func TestTwoFactor_EventEmissions(t *testing.T) {
	app, p, _ := setupTwoFactorTest(t, twofactor.WithSendOTP(func(ctx context.Context, userID string, otp string) error {
		return nil
	}))
	ctx := context.Background()
	userID := "usr_events_test"

	var enableBeforeEmitted, enableAfterEmitted, totpGeneratedEmitted, verifyBeforeEmitted, verifyAfterEmitted bool

	app.Events().Subscribe(twofactor.EventEnableTwoFactorBefore, func(ctx context.Context, payload any) {
		if req, ok := payload.(*twofactor.EnableTwoFactorBeforeEventPayload); ok && req.UserID == userID {
			enableBeforeEmitted = true
		}
	})

	app.Events().Subscribe(twofactor.EventEnableTwoFactorAfter, func(ctx context.Context, payload any) {
		if req, ok := payload.(*twofactor.EnableTwoFactorAfterEventPayload); ok && req.UserID == userID {
			enableAfterEmitted = true
		}
	})

	app.Events().Subscribe(twofactor.EventTOTPGenerated, func(ctx context.Context, payload any) {
		if req, ok := payload.(*twofactor.TOTPGeneratedEventPayload); ok && req.UserID == userID {
			totpGeneratedEmitted = true
		}
	})

	app.Events().Subscribe(twofactor.EventVerifyTOTPBefore, func(ctx context.Context, payload any) {
		if req, ok := payload.(*twofactor.VerifyTOTPBeforeEventPayload); ok && req.UserID == userID {
			verifyBeforeEmitted = true
		}
	})

	app.Events().Subscribe(twofactor.EventVerifyTOTPAfter, func(ctx context.Context, payload any) {
		if req, ok := payload.(*twofactor.VerifyTOTPAfterEventPayload); ok && req.UserID == userID {
			verifyAfterEmitted = true
		}
	})

	// Enable
	_, err := p.Enable(ctx, twofactor.EnableParams{UserID: userID})
	if err != nil {
		t.Fatalf("Enable failed: %v", err)
	}

	// Verify
	_, _ = p.VerifyTOTP(ctx, twofactor.VerifyTOTPParams{UserID: userID, Code: "000000"})

	if !enableBeforeEmitted {
		t.Error("Expected EventEnableTwoFactorBefore to be emitted")
	}
	if !enableAfterEmitted {
		t.Error("Expected EventEnableTwoFactorAfter to be emitted")
	}
	if !totpGeneratedEmitted {
		t.Error("Expected EventTOTPGenerated to be emitted")
	}
	if !verifyBeforeEmitted {
		t.Error("Expected EventVerifyTOTPBefore to be emitted")
	}
	if !verifyAfterEmitted {
		t.Error("Expected EventVerifyTOTPAfter to be emitted")
	}

	// Test Disable
	var disableBeforeEmitted, disableAfterEmitted bool
	app.Events().Subscribe(twofactor.EventDisableTwoFactorBefore, func(ctx context.Context, payload any) {
		if req, ok := payload.(*twofactor.DisableTwoFactorEventPayload); ok && req.UserID == userID {
			disableBeforeEmitted = true
		}
	})
	app.Events().Subscribe(twofactor.EventDisableTwoFactorAfter, func(ctx context.Context, payload any) {
		if req, ok := payload.(*twofactor.DisableTwoFactorEventPayload); ok && req.UserID == userID {
			disableAfterEmitted = true
		}
	})

	if err := p.Disable(ctx, twofactor.DisableParams{UserID: userID}); err != nil {
		t.Fatalf("Disable failed: %v", err)
	}

	if !disableBeforeEmitted || !disableAfterEmitted {
		t.Error("Expected Disable events to be emitted")
	}
}
