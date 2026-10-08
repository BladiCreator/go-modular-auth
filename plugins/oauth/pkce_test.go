package oauth_test

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/BladiCreator/go-modular-auth-oauth"
)

func TestGeneratePKCE(t *testing.T) {
	pair, err := oauth.GeneratePKCE()
	if err != nil {
		t.Fatalf("unexpected error generating pkce: %v", err)
	}

	if pair == nil {
		t.Fatal("expected non-nil pkce pair")
	}

	if len(pair.Verifier) < 43 || len(pair.Verifier) > 128 {
		t.Fatalf("verifier length %d is out of RFC 7636 bounds [43, 128]", len(pair.Verifier))
	}

	if pair.Method != oauth.PKCEMethodS256 {
		t.Fatalf("expected method %s, got %s", oauth.PKCEMethodS256, pair.Method)
	}

	expectedChallenge := oauth.ComputeS256Challenge(pair.Verifier)
	if pair.Challenge != expectedChallenge {
		t.Fatalf("challenge mismatch: got %s, want %s", pair.Challenge, expectedChallenge)
	}

	if !oauth.VerifyPKCE(pair.Verifier, pair.Challenge, pair.Method) {
		t.Fatal("pkce verification failed for generated pair")
	}
}

func TestVerifyPKCE(t *testing.T) {
	// RFC 7636 Appendix B test vector:
	// code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	// code_challenge = "E9Melhoa2OwvFrGMTJguCH5rtG6470-ZALxNjN4U9HY"
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	calculated := oauth.ComputeS256Challenge(verifier)
	if calculated != challenge {
		t.Fatalf("RFC 7636 vector mismatch: got %s, want %s", calculated, challenge)
	}

	if !oauth.VerifyPKCE(verifier, challenge, oauth.PKCEMethodS256) {
		t.Fatal("RFC 7636 test vector should verify successfully")
	}

	// Altered verifier must fail
	if oauth.VerifyPKCE(verifier+"x", challenge, oauth.PKCEMethodS256) {
		t.Fatal("tampered verifier should fail verification")
	}

	// Plain method
	if !oauth.VerifyPKCE(verifier, verifier, oauth.PKCEMethodPlain) {
		t.Fatal("plain method should match identical strings")
	}
	if oauth.VerifyPKCE(verifier, challenge, oauth.PKCEMethodPlain) {
		t.Fatal("plain method should fail non-matching strings")
	}

	// Empty input
	if oauth.VerifyPKCE("", challenge, oauth.PKCEMethodS256) {
		t.Fatal("empty verifier should fail")
	}
	if oauth.VerifyPKCE(verifier, "", oauth.PKCEMethodS256) {
		t.Fatal("empty challenge should fail")
	}

	// Unknown method
	if oauth.VerifyPKCE(verifier, challenge, "S512") {
		t.Fatal("unsupported method should fail")
	}
}

func TestComputeS256Challenge(t *testing.T) {
	v := "high_entropy_secret_1234567890"
	h := sha256.Sum256([]byte(v))
	expected := base64.RawURLEncoding.EncodeToString(h[:])

	actual := oauth.ComputeS256Challenge(v)
	if actual != expected {
		t.Fatalf("got %s, want %s", actual, expected)
	}
}
