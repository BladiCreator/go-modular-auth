package oidcprovider_test

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/BladiCreator/go-modular-auth/plugins/oidcprovider"
)

func TestPKCE_S256(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	if !oidcprovider.ValidatePKCE(verifier, challenge, "S256", false) {
		t.Errorf("expected ValidatePKCE with S256 to return true")
	}

	if oidcprovider.ValidatePKCE("invalid-verifier", challenge, "S256", false) {
		t.Errorf("expected ValidatePKCE with invalid verifier to return false")
	}
}

func TestPKCE_Plain(t *testing.T) {
	verifier := "my-plain-verifier-string"

	if !oidcprovider.ValidatePKCE(verifier, verifier, "PLAIN", true) {
		t.Errorf("expected ValidatePKCE with PLAIN and allowPlain=true to return true")
	}

	if oidcprovider.ValidatePKCE(verifier, verifier, "PLAIN", false) {
		t.Errorf("expected ValidatePKCE with PLAIN and allowPlain=false to return false")
	}
}

func TestUtils_ConstantTimeEqual(t *testing.T) {
	if !oidcprovider.ConstantTimeEqual("secret123", "secret123") {
		t.Errorf("expected ConstantTimeEqual to return true for identical strings")
	}

	if oidcprovider.ConstantTimeEqual("secret123", "secret456") {
		t.Errorf("expected ConstantTimeEqual to return false for different strings")
	}
}

func TestUtils_ValidateRedirectURI(t *testing.T) {
	allowed := []string{
		"https://app.example.com/callback",
		"http://localhost:3000/oauth/callback",
	}

	if !oidcprovider.ValidateRedirectURI("https://app.example.com/callback", allowed) {
		t.Errorf("expected valid redirect URI to match")
	}

	if oidcprovider.ValidateRedirectURI("https://attacker.com/callback", allowed) {
		t.Errorf("expected attacker redirect URI to be rejected")
	}
}

func TestUtils_ScopeParsing(t *testing.T) {
	parsed := oidcprovider.ParseScopes("openid profile email offline_access")
	if len(parsed) != 4 {
		t.Fatalf("expected 4 scopes, got %d", len(parsed))
	}

	if !oidcprovider.HasScope(parsed, "email") {
		t.Errorf("expected scope list to contain 'email'")
	}

	if !oidcprovider.HasAllScopes(parsed, []string{"openid", "email"}) {
		t.Errorf("expected HasAllScopes to return true for subset")
	}

	if oidcprovider.HasAllScopes(parsed, []string{"openid", "custom_scope"}) {
		t.Errorf("expected HasAllScopes to return false for missing scope")
	}
}
