package jwt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestAlgorithms_Symmetric(t *testing.T) {
	algs := []Algorithm{HS256, HS384, HS512}
	secret := []byte("super-secret-key-that-is-at-least-32-bytes-long!")
	payload := []byte("header.payload")

	for _, alg := range algs {
		t.Run(string(alg), func(t *testing.T) {
			sig, err := sign(alg, secret, payload)
			if err != nil {
				t.Fatalf("sign failed: %v", err)
			}
			if len(sig) == 0 {
				t.Fatal("empty signature")
			}

			// Valid verification
			err = verifySignature(alg, secret, payload, sig)
			if err != nil {
				t.Fatalf("verify failed: %v", err)
			}

			// Tampered payload
			err = verifySignature(alg, secret, []byte("tampered.payload"), sig)
			if err == nil {
				t.Fatal("expected failure on tampered payload")
			}

			// Tampered signature
			tamperedSig := make([]byte, len(sig))
			copy(tamperedSig, sig)
			tamperedSig[0] ^= 0xFF
			err = verifySignature(alg, secret, payload, tamperedSig)
			if err == nil {
				t.Fatal("expected failure on tampered signature")
			}
		})
	}
}

func TestAlgorithms_RSA(t *testing.T) {
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}

	algs := []Algorithm{RS256, RS384, RS512, PS256, PS384, PS512}
	payload := []byte("test-rsa-signing-payload")

	for _, alg := range algs {
		t.Run(string(alg), func(t *testing.T) {
			sig, err := sign(alg, rsaPriv, payload)
			if err != nil {
				t.Fatalf("sign failed: %v", err)
			}

			// Verify with public key
			err = verifySignature(alg, &rsaPriv.PublicKey, payload, sig)
			if err != nil {
				t.Fatalf("verify failed: %v", err)
			}

			// Verify with private key also works (extracts public key)
			err = verifySignature(alg, rsaPriv, payload, sig)
			if err != nil {
				t.Fatalf("verify with private key failed: %v", err)
			}

			// Tampered payload
			err = verifySignature(alg, &rsaPriv.PublicKey, []byte("tampered"), sig)
			if err == nil {
				t.Fatal("expected failure on tampered payload")
			}
		})
	}
}

func TestAlgorithms_ECDSA(t *testing.T) {
	curves := []struct {
		alg   Algorithm
		curve elliptic.Curve
	}{
		{ES256, elliptic.P256()},
		{ES384, elliptic.P384()},
		{ES512, elliptic.P521()},
	}

	payload := []byte("ecdsa-signing-payload")

	for _, tc := range curves {
		t.Run(string(tc.alg), func(t *testing.T) {
			priv, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatalf("generate ecdsa key: %v", err)
			}

			sig, err := sign(tc.alg, priv, payload)
			if err != nil {
				t.Fatalf("sign failed: %v", err)
			}

			err = verifySignature(tc.alg, &priv.PublicKey, payload, sig)
			if err != nil {
				t.Fatalf("verify failed: %v", err)
			}

			err = verifySignature(tc.alg, &priv.PublicKey, []byte("tampered"), sig)
			if err == nil {
				t.Fatal("expected error on tampered payload")
			}
		})
	}
}

func TestAlgorithms_EdDSA(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}

	payload := []byte("eddsa-signing-payload")

	sig, err := sign(EdDSA, priv, payload)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	err = verifySignature(EdDSA, pub, payload, sig)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}

	err = verifySignature(EdDSA, pub, []byte("tampered"), sig)
	if err == nil {
		t.Fatal("expected error on tampered payload")
	}
}
