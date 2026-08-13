package twofactor_test

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth/plugins/twofactor"
)

func TestCrypto_Base32SecretGeneration(t *testing.T) {
	secret, err := twofactor.GenerateBase32Secret(20)
	if err != nil {
		t.Fatalf("GenerateBase32Secret failed: %v", err)
	}

	if secret == "" {
		t.Fatal("Expected non-empty secret")
	}

	// Should decode without error
	decoded, err := twofactor.DecodeBase32Secret(secret)
	if err != nil {
		t.Fatalf("DecodeBase32Secret failed for generated secret: %v", err)
	}

	if len(decoded) != 20 {
		t.Errorf("Expected 20 bytes decoded, got %d", len(decoded))
	}

	// Test decoding with spaces and lowercase
	secretWithSpaces := "  " + strings.ToLower(secret[:10]) + " " + secret[10:] + "  "
	decodedClean, err := twofactor.DecodeBase32Secret(secretWithSpaces)
	if err != nil {
		t.Fatalf("DecodeBase32Secret failed on dirty string: %v", err)
	}
	if string(decodedClean) != string(decoded) {
		t.Errorf("Decoded dirty string did not match original")
	}
}

func TestCrypto_TOTPGenerationAndValidation(t *testing.T) {
	// RFC 6238 Test Seed: "12345678901234567890" (20 bytes)
	rawSeed := []byte("12345678901234567890")
	base32Secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(rawSeed)

	// RFC 6238 Appendix B test vectors for HMAC-SHA1, 8 digits, period 30:
	// T = 59s -> TC = 1 -> "94287082"
	// T = 1111111109s -> TC = 37037036 -> "07081804"
	// T = 1234567890s -> TC = 41152263 -> "89005924"
	testVectors := []struct {
		timestamp int64
		expected  string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1234567890, "89005924"},
	}

	for _, tc := range testVectors {
		code, err := twofactor.GenerateTOTPCode(base32Secret, tc.timestamp, 30, 8, twofactor.AlgorithmSHA1)
		if err != nil {
			t.Fatalf("GenerateTOTPCode failed for timestamp %d: %v", tc.timestamp, err)
		}
		if code != tc.expected {
			t.Errorf("For timestamp %d: expected %s, got %s", tc.timestamp, tc.expected, code)
		}
	}
}

func TestCrypto_TOTPAlgorithms(t *testing.T) {
	secret, err := twofactor.GenerateBase32Secret(32)
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}

	now := time.Now().Unix()

	// Test SHA1, SHA256, SHA512
	codeSHA1, err := twofactor.GenerateTOTPCode(secret, now, 30, 6, twofactor.AlgorithmSHA1)
	if err != nil || len(codeSHA1) != 6 {
		t.Errorf("SHA1 TOTP failed: %v", err)
	}

	codeSHA256, err := twofactor.GenerateTOTPCode(secret, now, 30, 6, twofactor.AlgorithmSHA256)
	if err != nil || len(codeSHA256) != 6 {
		t.Errorf("SHA256 TOTP failed: %v", err)
	}

	codeSHA512, err := twofactor.GenerateTOTPCode(secret, now, 30, 6, twofactor.AlgorithmSHA512)
	if err != nil || len(codeSHA512) != 6 {
		t.Errorf("SHA512 TOTP failed: %v", err)
	}

	// Validate current code
	if !twofactor.ValidateTOTPCode(secret, codeSHA1, 30, 6, twofactor.AlgorithmSHA1) {
		t.Error("Expected ValidateTOTPCode to succeed for current SHA1 code")
	}
	if !twofactor.ValidateTOTPCode(secret, codeSHA256, 30, 6, twofactor.AlgorithmSHA256) {
		t.Error("Expected ValidateTOTPCode to succeed for current SHA256 code")
	}
	if !twofactor.ValidateTOTPCode(secret, codeSHA512, 30, 6, twofactor.AlgorithmSHA512) {
		t.Error("Expected ValidateTOTPCode to succeed for current SHA512 code")
	}

	// Invalid code must fail
	if twofactor.ValidateTOTPCode(secret, "000000", 30, 6, twofactor.AlgorithmSHA1) && codeSHA1 != "000000" {
		t.Error("Expected ValidateTOTPCode to reject invalid code")
	}
}

func TestCrypto_BuildTOTPURI(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	uri := twofactor.BuildTOTPURI("Acme Corp", "user@example.com", secret, 6, 30, twofactor.AlgorithmSHA1)

	if !strings.HasPrefix(uri, "otpauth://totp/Acme%20Corp:user@example.com?") {
		t.Errorf("Unexpected URI prefix: %s", uri)
	}
	if !strings.Contains(uri, "secret=JBSWY3DPEHPK3PXP") {
		t.Errorf("URI missing secret: %s", uri)
	}
	if !strings.Contains(uri, "issuer=Acme+Corp") {
		t.Errorf("URI missing issuer param: %s", uri)
	}
	if !strings.Contains(uri, "digits=6") || !strings.Contains(uri, "period=30") {
		t.Errorf("URI missing digits/period: %s", uri)
	}
}

func TestCrypto_BackupCodes(t *testing.T) {
	codes, err := twofactor.GenerateBackupCodes(10, 10)
	if err != nil {
		t.Fatalf("GenerateBackupCodes failed: %v", err)
	}

	if len(codes) != 10 {
		t.Fatalf("Expected 10 backup codes, got %d", len(codes))
	}

	// Each code should have a hyphen
	for _, code := range codes {
		if !strings.Contains(code, "-") {
			t.Errorf("Expected formatted code with hyphen, got: %s", code)
		}
	}

	// Test ValidateBackupCode with normalized and case-insensitive inputs
	firstCode := codes[0]
	idx, valid := twofactor.ValidateBackupCode(codes, firstCode)
	if !valid || idx != 0 {
		t.Errorf("ValidateBackupCode failed for exact code: idx=%d, valid=%t", idx, valid)
	}

	// Dirty input (lowercase, without hyphen, with spaces)
	dirtyInput := "  " + strings.ToLower(strings.ReplaceAll(firstCode, "-", "")) + "  "
	idx, valid = twofactor.ValidateBackupCode(codes, dirtyInput)
	if !valid || idx != 0 {
		t.Errorf("ValidateBackupCode failed for dirty input: idx=%d, valid=%t", idx, valid)
	}

	// Non-existent code
	_, valid = twofactor.ValidateBackupCode(codes, "INVALID-CODE")
	if valid {
		t.Error("Expected ValidateBackupCode to fail for non-existent code")
	}
}

func TestCrypto_RandomNumericCode(t *testing.T) {
	code, err := twofactor.GenerateRandomNumericCode(6)
	if err != nil {
		t.Fatalf("GenerateRandomNumericCode failed: %v", err)
	}
	if len(code) != 6 {
		t.Errorf("Expected 6 digits, got: %s", code)
	}

	code8, err := twofactor.GenerateRandomNumericCode(8)
	if err != nil {
		t.Fatalf("GenerateRandomNumericCode(8) failed: %v", err)
	}
	if len(code8) != 8 {
		t.Errorf("Expected 8 digits, got: %s", code8)
	}
}

func TestCrypto_TrustedDeviceTokens(t *testing.T) {
	secret := "my-cryptographic-device-secret-32b"
	userID := "usr_alice_123"
	deviceID := "dev_laptop_macbook"
	expiresAt := time.Now().Add(1 * time.Hour)

	token := twofactor.GenerateTrustDeviceToken(userID, deviceID, secret, expiresAt)
	if token == "" || !strings.Contains(token, ".") {
		t.Fatalf("Invalid generated trust device token: %s", token)
	}

	// Valid token check
	if !twofactor.VerifyTrustDeviceToken(token, userID, deviceID, secret) {
		t.Error("Expected VerifyTrustDeviceToken to succeed")
	}

	// Wrong user ID
	if twofactor.VerifyTrustDeviceToken(token, "usr_bob_456", deviceID, secret) {
		t.Error("Expected VerifyTrustDeviceToken to reject wrong user ID")
	}

	// Wrong device ID
	if twofactor.VerifyTrustDeviceToken(token, userID, "dev_other_phone", secret) {
		t.Error("Expected VerifyTrustDeviceToken to reject wrong device ID")
	}

	// Wrong secret
	if twofactor.VerifyTrustDeviceToken(token, userID, deviceID, "tampered-secret") {
		t.Error("Expected VerifyTrustDeviceToken to reject wrong secret")
	}

	// Expired token
	expiredToken := twofactor.GenerateTrustDeviceToken(userID, deviceID, secret, time.Now().Add(-10*time.Minute))
	if twofactor.VerifyTrustDeviceToken(expiredToken, userID, deviceID, secret) {
		t.Error("Expected VerifyTrustDeviceToken to reject expired token")
	}
}
