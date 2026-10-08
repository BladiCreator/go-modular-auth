package jwt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"
)

func TestBuildJWKS(t *testing.T) {
	km := NewKeyManager()

	// 1. RSA Key
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa: %v", err)
	}
	rsaKey, _ := NewRSAKey("rsa-pub-1", RS256, rsaPriv)
	_ = km.AddKey(rsaKey)

	// 2. ECDSA Key
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa: %v", err)
	}
	ecKey, _ := NewECDSAKey("ec-pub-1", ES256, ecPriv)
	_ = km.AddKey(ecKey)

	// 3. Ed25519 Key
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	edKey, _ := NewEd25519Key("ed-pub-1", edPriv)
	_ = km.AddKey(edKey)

	// 4. HMAC Key (must NOT be exported in JWKS)
	hmacKey, _ := NewHMACKey("hmac-secret", HS256, []byte("secret-key-that-is-at-least-32-bytes-long!"))
	_ = km.AddKey(hmacKey)

	jwks, err := BuildJWKS(km)
	if err != nil {
		t.Fatalf("BuildJWKS failed: %v", err)
	}

	// Must contain exactly 3 asymmetric keys, excluding HMAC
	if len(jwks.Keys) != 3 {
		t.Fatalf("expected 3 public keys in JWKS, got %d", len(jwks.Keys))
	}

	for _, k := range jwks.Keys {
		if k.Kid == "hmac-secret" {
			t.Fatal("security violation: symmetric HMAC key was exported in JWKS!")
		}
	}

	jsonBytes, err := jwks.JSON()
	if err != nil {
		t.Fatalf("serialize JWKS JSON: %v", err)
	}

	var parsed map[string][]map[string]any
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		t.Fatalf("unmarshal JWKS JSON: %v", err)
	}

	if len(parsed["keys"]) != 3 {
		t.Fatalf("expected 3 parsed keys, got %d", len(parsed["keys"]))
	}
}
