package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
)

func TestKeyManager_Basics(t *testing.T) {
	km := NewKeyManager()

	k1, err := NewHMACKey("k1", HS256, []byte("secret-key-that-is-at-least-32-bytes-long!"))
	if err != nil {
		t.Fatalf("new hmac key: %v", err)
	}

	if err := km.AddKey(k1); err != nil {
		t.Fatalf("add key: %v", err)
	}

	// First key added should automatically be active
	active, err := km.GetActiveSigningKey()
	if err != nil {
		t.Fatalf("get active key: %v", err)
	}
	if active.ID != "k1" {
		t.Fatalf("expected active key k1, got %s", active.ID)
	}

	// Add second key
	k2, err := NewHMACKey("k2", HS384, []byte("second-secret-key-at-least-32-bytes-long!!"))
	if err != nil {
		t.Fatalf("new second hmac key: %v", err)
	}
	if err := km.AddKey(k2); err != nil {
		t.Fatalf("add second key: %v", err)
	}

	// Rotate to k2
	if err := km.SetActiveSigningKey("k2"); err != nil {
		t.Fatalf("set active key: %v", err)
	}
	active, _ = km.GetActiveSigningKey()
	if active.ID != "k2" {
		t.Fatalf("expected active key k2, got %s", active.ID)
	}
}

func TestKeyManager_AlgorithmConfusionPrevention(t *testing.T) {
	km := NewKeyManager()

	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa: %v", err)
	}

	rsaKey, err := NewRSAKey("rsa-1", RS256, rsaPriv)
	if err != nil {
		t.Fatalf("new rsa key: %v", err)
	}

	if err := km.AddKey(rsaKey); err != nil {
		t.Fatalf("add rsa key: %v", err)
	}

	// Attacker attempts to verify RSA key using HMAC HS256 (classic CVE-2015-9235 vulnerability)
	_, err = km.GetVerificationKey("rsa-1", HS256)
	if !errors.Is(err, ErrAlgorithmMismatch) {
		t.Fatalf("expected ErrAlgorithmMismatch when requesting HS256 on RSA key, got: %v", err)
	}

	// Attacker attempts to verify without kid when multiple keys exist
	hmacKey, err := NewHMACKey("hmac-1", HS256, []byte("secret-key-that-is-at-least-32-bytes-long!"))
	if err != nil {
		t.Fatalf("new hmac key: %v", err)
	}
	_ = km.AddKey(hmacKey)

	_, err = km.GetVerificationKey("", HS256)
	if !errors.Is(err, ErrKeyIDRequired) {
		t.Fatalf("expected ErrKeyIDRequired when multiple keys exist and kid is omitted, got: %v", err)
	}
}
