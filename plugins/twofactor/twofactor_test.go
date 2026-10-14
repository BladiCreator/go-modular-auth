package twofactor_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	twofactor "github.com/BladiCreator/go-modular-auth-twofactor"
)

func newTestService(t *testing.T) twofactor.TwoFactor {
	t.Helper()
	key, err := twofactor.GenerateRandomKey()
	if err != nil {
		t.Fatalf("GenerateRandomKey failed: %v", err)
	}
	protector, err := twofactor.NewAESGCMProtector(key)
	if err != nil {
		t.Fatalf("NewAESGCMProtector failed: %v", err)
	}

	cfg := twofactor.Config{
		Protector:                 protector,
		Issuer:                    "TestApp",
		StepDuration:              30 * time.Second,
		SkewSteps:                 1,
		ChallengeTTL:              5 * time.Minute,
		DefaultRecoveryCodesCount: 8,
	}

	return twofactor.NewServiceForTesting(cfg)
}

func createServiceForTest(cfg twofactor.Config) twofactor.TwoFactor {
	// Use exported helper or module test
	return twofactor.NewServiceForTesting(cfg)
}

func TestCrypto_TOTPCalculationAndSkew(t *testing.T) {
	secret, err := twofactor.GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret failed: %v", err)
	}

	now := time.Now().UTC()
	currentStep := now.Unix() / 30

	code, err := twofactor.CalculateTOTP(secret, currentStep)
	if err != nil {
		t.Fatalf("CalculateTOTP failed: %v", err)
	}
	if len(code) != 6 {
		t.Fatalf("expected 6-digit code, got %q", code)
	}

	// Validate matching current step
	step, ok := twofactor.ValidateTOTP(secret, code, now, 30*time.Second, 1)
	if !ok || step != currentStep {
		t.Errorf("expected validation success for current step, got step=%d ok=%v", step, ok)
	}

	// Validate with skew -1 step (30 seconds in past)
	pastNow := now.Add(30 * time.Second) // currentStep is now 1 step in the past relative to pastNow
	step, ok = twofactor.ValidateTOTP(secret, code, pastNow, 30*time.Second, 1)
	if !ok || step != currentStep {
		t.Errorf("expected validation success with 1 step skew, got step=%d ok=%v", step, ok)
	}

	// Out of skew window (3 steps in future)
	futureNow := now.Add(120 * time.Second)
	_, ok = twofactor.ValidateTOTP(secret, code, futureNow, 30*time.Second, 1)
	if ok {
		t.Error("expected validation to fail for out-of-skew time")
	}
}

func TestCrypto_AESGCMProtector(t *testing.T) {
	key, _ := twofactor.GenerateRandomKey()
	p, err := twofactor.NewAESGCMProtector(key)
	if err != nil {
		t.Fatalf("NewAESGCMProtector failed: %v", err)
	}

	plaintext := []byte("JBSWY3DPEHPK3PXP")
	encrypted, err := p.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if encrypted == string(plaintext) {
		t.Fatal("encrypted text must not match plaintext")
	}

	decrypted, err := p.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Fatalf("decrypted %q != plaintext %q", string(decrypted), string(plaintext))
	}
}

func TestCrypto_RecoveryCodeHashing(t *testing.T) {
	code, err := twofactor.GenerateRecoveryCode()
	if err != nil {
		t.Fatalf("GenerateRecoveryCode failed: %v", err)
	}
	if len(code) != 14 { // "XXXX-XXXX-XXXX" = 12 chars + 2 dashes
		t.Fatalf("unexpected recovery code format: %q", code)
	}

	hash1 := twofactor.HashRecoveryCode(code)
	// Same code lowercase without dashes should produce the same hash
	lower := strings.ToLower(strings.ReplaceAll(code, "-", ""))
	hash2 := twofactor.HashRecoveryCode(lower)

	if hash1 != hash2 {
		t.Fatalf("hash of normalized code must match: %s != %s", hash1, hash2)
	}
}

func TestTwoFactor_EnrollmentAndConfirmation(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	userID := "usr_100"

	// Initial status should be disabled
	status, err := svc.GetStatus(ctx, userID)
	if err != nil {
		t.Fatalf("GetStatus failed: %v", err)
	}
	if status.Enabled {
		t.Error("expected 2FA to be initially disabled")
	}

	// Verify before enrollment must fail
	_, err = svc.VerifyTOTP(ctx, userID, "123456")
	if err != twofactor.ErrTwoFactorNotEnabled {
		t.Fatalf("expected ErrTwoFactorNotEnabled, got %v", err)
	}

	// Enroll
	enrollment, err := svc.EnrollTOTP(ctx, userID, twofactor.WithEnrollLabel("Work Mobile"))
	if err != nil {
		t.Fatalf("EnrollTOTP failed: %v", err)
	}
	if enrollment.Secret == "" || enrollment.FactorID == "" || enrollment.ProvisioningURI == "" {
		t.Fatalf("incomplete enrollment: %+v", enrollment)
	}

	// Status still disabled because factor is unconfirmed
	status, _ = svc.GetStatus(ctx, userID)
	if status.Enabled {
		t.Error("expected 2FA to remain disabled until confirmed")
	}

	// Generate valid code
	now := time.Now().UTC()
	currentStep := now.Unix() / 30
	code, _ := twofactor.CalculateTOTP(enrollment.Secret, currentStep)

	// Confirm with bad code fails
	err = svc.ConfirmTOTP(ctx, userID, enrollment.FactorID, "000000")
	if err != twofactor.ErrInvalidCode {
		t.Fatalf("expected ErrInvalidCode for wrong code, got %v", err)
	}

	// Confirm with valid code
	err = svc.ConfirmTOTP(ctx, userID, enrollment.FactorID, code)
	if err != nil {
		t.Fatalf("ConfirmTOTP failed: %v", err)
	}

	// Second confirmation should fail
	err = svc.ConfirmTOTP(ctx, userID, enrollment.FactorID, code)
	if err != twofactor.ErrFactorAlreadyConfirmed {
		t.Fatalf("expected ErrFactorAlreadyConfirmed, got %v", err)
	}

	// Now 2FA is enabled
	status, _ = svc.GetStatus(ctx, userID)
	if !status.Enabled {
		t.Error("expected 2FA to be enabled after confirmation")
	}
	if len(status.Factors) != 1 || !status.Factors[0].Confirmed {
		t.Fatalf("expected 1 confirmed factor, got %+v", status.Factors)
	}
}

func TestTwoFactor_OTPReplayPrevention(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	userID := "usr_replay"

	enrollment, err := svc.EnrollTOTP(ctx, userID)
	if err != nil {
		t.Fatalf("EnrollTOTP failed: %v", err)
	}

	now := time.Now().UTC()
	currentStep := now.Unix() / 30
	code, _ := twofactor.CalculateTOTP(enrollment.Secret, currentStep)

	// Confirm factor (consumes currentStep)
	if err := svc.ConfirmTOTP(ctx, userID, enrollment.FactorID, code); err != nil {
		t.Fatalf("ConfirmTOTP failed: %v", err)
	}

	// Verify using the SAME code in the SAME step must fail with replay detected!
	_, err = svc.VerifyTOTP(ctx, userID, code)
	if err != twofactor.ErrReplayDetected {
		t.Fatalf("expected ErrReplayDetected on immediate replay, got %v", err)
	}
}

func TestTwoFactor_RecoveryCodesLifecycle(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	userID := "usr_rec"

	// Generate 5 recovery codes
	codes, err := svc.GenerateRecoveryCodes(ctx, userID, 5)
	if err != nil {
		t.Fatalf("GenerateRecoveryCodes failed: %v", err)
	}
	if len(codes) != 5 {
		t.Fatalf("expected 5 codes, got %d", len(codes))
	}

	count, _ := svc.GetRemainingRecoveryCodesCount(ctx, userID)
	if count != 5 {
		t.Fatalf("expected 5 remaining codes, got %d", count)
	}

	// Verify first code
	res, err := svc.VerifyRecoveryCode(ctx, userID, codes[0])
	if err != nil {
		t.Fatalf("VerifyRecoveryCode failed: %v", err)
	}
	if res.AssuranceLevel != twofactor.AAL2 || res.FactorType != twofactor.FactorTypeRecoveryCodes {
		t.Errorf("unexpected verify result: %+v", res)
	}

	// Remaining count drops to 4
	count, _ = svc.GetRemainingRecoveryCodesCount(ctx, userID)
	if count != 4 {
		t.Fatalf("expected 4 remaining codes, got %d", count)
	}

	// Reusing same code fails
	_, err = svc.VerifyRecoveryCode(ctx, userID, codes[0])
	if err != twofactor.ErrRecoveryCodeNotFound {
		t.Fatalf("expected ErrRecoveryCodeNotFound on used code, got %v", err)
	}

	// Rotate recovery codes
	newCodes, err := svc.RotateRecoveryCodes(ctx, userID)
	if err != nil {
		t.Fatalf("RotateRecoveryCodes failed: %v", err)
	}
	if len(newCodes) != 8 { // Default count is 8
		t.Fatalf("expected 8 rotated codes, got %d", len(newCodes))
	}

	// Old unused code (codes[1]) should no longer work
	_, err = svc.VerifyRecoveryCode(ctx, userID, codes[1])
	if err != twofactor.ErrRecoveryCodeNotFound {
		t.Fatalf("expected ErrRecoveryCodeNotFound for rotated old code, got %v", err)
	}

	// New code works
	_, err = svc.VerifyRecoveryCode(ctx, userID, newCodes[0])
	if err != nil {
		t.Fatalf("VerifyRecoveryCode with new rotated code failed: %v", err)
	}
}

func TestTwoFactor_Challenges(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	userID := "usr_ch"

	// Challenge creation before 2FA enabled fails
	_, err := svc.CreateChallenge(ctx, userID)
	if err != twofactor.ErrTwoFactorNotEnabled {
		t.Fatalf("expected ErrTwoFactorNotEnabled, got %v", err)
	}

	// Enroll and confirm TOTP
	enrollment, _ := svc.EnrollTOTP(ctx, userID)
	now := time.Now().UTC()
	code, _ := twofactor.CalculateTOTP(enrollment.Secret, now.Unix()/30)
	_ = svc.ConfirmTOTP(ctx, userID, enrollment.FactorID, code)

	// Create challenge
	ch, err := svc.CreateChallenge(ctx, userID)
	if err != nil {
		t.Fatalf("CreateChallenge failed: %v", err)
	}
	if ch.ID == "" || ch.UserID != userID {
		t.Fatalf("unexpected challenge: %+v", ch)
	}

	// Generate a recovery code to verify the challenge with
	recCodes, _ := svc.GenerateRecoveryCodes(ctx, userID, 3)

	// Verify challenge using recovery code
	res, err := svc.VerifyChallenge(ctx, ch.ID, recCodes[0])
	if err != nil {
		t.Fatalf("VerifyChallenge failed: %v", err)
	}
	if res.AssuranceLevel != twofactor.AAL2 {
		t.Errorf("expected AAL2, got %v", res.AssuranceLevel)
	}

	// Second verification of same challenge fails
	_, err = svc.VerifyChallenge(ctx, ch.ID, recCodes[1])
	if err != twofactor.ErrChallengeAlreadyUsed {
		t.Fatalf("expected ErrChallengeAlreadyUsed, got %v", err)
	}
}

func TestTwoFactor_DisableAndFactorRemoval(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	userID := "usr_disable"

	enrollment, _ := svc.EnrollTOTP(ctx, userID)
	now := time.Now().UTC()
	code, _ := twofactor.CalculateTOTP(enrollment.Secret, now.Unix()/30)
	_ = svc.ConfirmTOTP(ctx, userID, enrollment.FactorID, code)
	_, _ = svc.GenerateRecoveryCodes(ctx, userID, 5)

	enabled, _ := svc.IsEnabled(ctx, userID)
	if !enabled {
		t.Fatal("expected 2FA enabled")
	}

	// Disable
	if err := svc.Disable(ctx, userID); err != nil {
		t.Fatalf("Disable failed: %v", err)
	}

	enabledAfter, _ := svc.IsEnabled(ctx, userID)
	if enabledAfter {
		t.Error("expected 2FA disabled after Disable()")
	}

	count, _ := svc.GetRemainingRecoveryCodesCount(ctx, userID)
	if count != 0 {
		t.Errorf("expected 0 recovery codes, got %d", count)
	}
}

func TestTwoFactor_AssuranceLevelContext(t *testing.T) {
	ctx := context.Background()

	// Default context is AAL1
	lvl, ok := twofactor.AssuranceLevelFrom(ctx)
	if ok || lvl != twofactor.AAL1 {
		t.Errorf("expected default AAL1, got %v ok=%v", lvl, ok)
	}
	if err := twofactor.RequireAAL2(ctx); err != twofactor.ErrAssuranceLevelInsufficient {
		t.Errorf("expected ErrAssuranceLevelInsufficient, got %v", err)
	}

	// With AAL2
	ctxAAL2 := twofactor.WithAssuranceLevel(ctx, twofactor.AAL2)
	lvl, ok = twofactor.AssuranceLevelFrom(ctxAAL2)
	if !ok || lvl != twofactor.AAL2 {
		t.Errorf("expected AAL2, got %v ok=%v", lvl, ok)
	}
	if err := twofactor.RequireAAL2(ctxAAL2); err != nil {
		t.Errorf("expected RequireAAL2 to pass, got %v", err)
	}
}

func TestTwoFactor_Concurrency(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	userID := "usr_concurrent"

	codes, err := svc.GenerateRecoveryCodes(ctx, userID, 50)
	if err != nil {
		t.Fatalf("GenerateRecoveryCodes failed: %v", err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, len(codes))

	// Redeem 50 codes concurrently
	for _, c := range codes {
		wg.Add(1)
		go func(code string) {
			defer wg.Done()
			_, err := svc.VerifyRecoveryCode(ctx, userID, code)
			if err != nil {
				errs <- err
			}
		}(c)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent verify error: %v", err)
	}

	remaining, _ := svc.GetRemainingRecoveryCodesCount(ctx, userID)
	if remaining != 0 {
		t.Errorf("expected 0 remaining codes, got %d", remaining)
	}
}
