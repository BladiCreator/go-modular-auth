package jwt_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	jwt "github.com/BladiCreator/go-modular-auth-jwt"
	"github.com/BladiCreator/go-modular-auth-jwt/plugins"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapter/memory"
	corecpmem "github.com/BladiCreator/go-modular-auth/cache/memory"
)

func setupTestAuth(t *testing.T, opts ...jwt.Option) (*auth.Auth, jwt.JWT) {
	t.Helper()

	cacheAdapter := corecpmem.New()
	dbAdapter := adaptermem.New()

	app, err := auth.New(auth.Config{
		Adapter: dbAdapter,
		Cache:   cacheAdapter,
		Plugins: []auth.PluginModule{jwt.New(opts...)},
	})
	if err != nil {
		t.Fatalf("failed to initialize auth core: %v", err)
	}

	plugin, err := auth.Get[plugins.JWT](app)
	if err != nil {
		t.Fatalf("failed to retrieve plugins.JWT: %v", err)
	}

	return app, plugin
}

func defaultHMACKey(t *testing.T, id string) jwt.Key {
	t.Helper()
	k, err := jwt.NewHMACKey(id, jwt.HS256, []byte("super-secret-key-at-least-32-bytes-long!"))
	if err != nil {
		t.Fatalf("failed to create hmac key: %v", err)
	}
	return k
}

func TestJWT_RegistrationAndLookup(t *testing.T) {
	k := defaultHMACKey(t, "key-1")
	app, plugin := setupTestAuth(t, jwt.WithKey(k))

	if app == nil {
		t.Fatal("expected non-nil Auth engine")
	}
	if plugin == nil {
		t.Fatal("expected non-nil JWT plugin capability")
	}
}

func TestJWT_IssueAndVerify_HMAC(t *testing.T) {
	k := defaultHMACKey(t, "key-1")
	_, plugin := setupTestAuth(t,
		jwt.WithKey(k),
		jwt.WithIssuer("https://auth.example.com"),
		jwt.WithDefaultAudience("https://api.example.com"),
		jwt.WithDefaultTTL(10*time.Minute),
	)

	ctx := context.Background()
	claims := jwt.Claims{
		Subject: "usr_42",
		Custom: map[string]any{
			"role": "admin",
		},
	}

	tokenStr, err := plugin.Issue(ctx, claims)
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}
	if tokenStr == "" {
		t.Fatal("empty token string returned")
	}

	// Verify token
	verified, err := plugin.Verify(ctx, tokenStr,
		jwt.WithExpectedIssuer("https://auth.example.com"),
		jwt.WithExpectedAudience("https://api.example.com"),
		jwt.WithExpectedSubject("usr_42"),
	)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if verified.Subject != "usr_42" {
		t.Fatalf("expected subject usr_42, got %s", verified.Subject)
	}
	if verified.Issuer != "https://auth.example.com" {
		t.Fatalf("expected issuer https://auth.example.com, got %s", verified.Issuer)
	}
	if !verified.Audience.Contains("https://api.example.com") {
		t.Fatalf("expected audience https://api.example.com, got %v", verified.Audience)
	}
	if verified.Custom["role"] != "admin" {
		t.Fatalf("expected custom claim role=admin, got %v", verified.Custom["role"])
	}
	if verified.ID == "" {
		t.Fatal("expected auto-generated JTI")
	}
}

func TestJWT_Security_UnsignedTokenRejection(t *testing.T) {
	k := defaultHMACKey(t, "key-1")
	_, plugin := setupTestAuth(t, jwt.WithKey(k))
	ctx := context.Background()

	// 1. alg: "none"
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"admin"}`))
	noneToken := header + "." + payload + "."

	_, err := plugin.Verify(ctx, noneToken)
	if !errors.Is(err, jwt.ErrUnsignedTokenNotAllowed) {
		t.Fatalf("expected ErrUnsignedTokenNotAllowed, got %v", err)
	}

	// 2. empty alg
	headerEmpty := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"","typ":"JWT"}`))
	emptyToken := headerEmpty + "." + payload + "."
	_, err = plugin.Verify(ctx, emptyToken)
	if !errors.Is(err, jwt.ErrUnsignedTokenNotAllowed) {
		t.Fatalf("expected ErrUnsignedTokenNotAllowed on empty alg, got %v", err)
	}
}

func TestJWT_Security_AlgorithmConfusionAttack(t *testing.T) {
	// Setup plugin with RSA signing key
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa: %v", err)
	}
	rsaKey, err := jwt.NewRSAKey("rsa-srv-1", jwt.RS256, rsaPriv)
	if err != nil {
		t.Fatalf("new rsa key: %v", err)
	}

	_, plugin := setupTestAuth(t,
		jwt.WithKey(rsaKey),
		jwt.WithAllowedAlgorithms(jwt.RS256, jwt.HS256), // Even if HS256 is in allowed list!
	)
	ctx := context.Background()

	// Legitimate RSA token works
	legitToken, err := plugin.Issue(ctx, jwt.Claims{Subject: "alice"})
	if err != nil {
		t.Fatalf("issue legit rsa token: %v", err)
	}
	if _, err := plugin.Verify(ctx, legitToken); err != nil {
		t.Fatalf("verify legit rsa token failed: %v", err)
	}

	// Attacker crafts forged token using public key as HMAC secret:
	// Attacker sets alg: HS256 and kid: rsa-srv-1
	forgedHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT","kid":"rsa-srv-1"}`))
	forgedPayload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"admin-attacker"}`))
	forgedSigningInput := forgedHeader + "." + forgedPayload

	// Attacker signs using RSA public key bytes with HMAC
	attackerSecret := rsaPriv.PublicKey.N.Bytes()
	kAttacker, _ := jwt.NewHMACKey("tmp", jwt.HS256, attackerSecret)
	_ = kAttacker

	forgedSig := base64.RawURLEncoding.EncodeToString([]byte("attacker-hmac-signature-bytes-xyz-1234567890"))
	forgedToken := forgedSigningInput + "." + forgedSig

	// Plugin MUST strictly reject the token with ErrAlgorithmMismatch
	_, err = plugin.Verify(ctx, forgedToken)
	if !errors.Is(err, jwt.ErrAlgorithmMismatch) {
		t.Fatalf("security violation: expected ErrAlgorithmMismatch, got %v", err)
	}
}

func TestJWT_KeyRotation(t *testing.T) {
	km := jwt.NewKeyManager()

	k1, err := jwt.NewHMACKey("key-2026-v1", jwt.HS256, []byte("key-secret-2026-v1-must-be-32-bytes!"))
	if err != nil {
		t.Fatalf("key 1: %v", err)
	}
	_ = km.AddKey(k1)

	_, plugin := setupTestAuth(t, jwt.WithKeyManager(km))
	ctx := context.Background()

	// Issue token with key 1
	token1, err := plugin.Issue(ctx, jwt.Claims{Subject: "bob"})
	if err != nil {
		t.Fatalf("issue token 1: %v", err)
	}

	// Rotate to key 2
	k2, err := jwt.NewHMACKey("key-2026-v2", jwt.HS384, []byte("key-secret-2026-v2-must-be-32-bytes!"))
	if err != nil {
		t.Fatalf("key 2: %v", err)
	}
	if err := km.RotateSigningKey(k2); err != nil {
		t.Fatalf("rotate key: %v", err)
	}

	// Issue token with key 2
	token2, err := plugin.Issue(ctx, jwt.Claims{Subject: "charlie"})
	if err != nil {
		t.Fatalf("issue token 2: %v", err)
	}

	// Both tokens should verify successfully
	claims1, err := plugin.Verify(ctx, token1)
	if err != nil {
		t.Fatalf("token 1 verify failed after rotation: %v", err)
	}
	if claims1.Subject != "bob" {
		t.Fatalf("expected bob, got %s", claims1.Subject)
	}

	claims2, err := plugin.Verify(ctx, token2)
	if err != nil {
		t.Fatalf("token 2 verify failed: %v", err)
	}
	if claims2.Subject != "charlie" {
		t.Fatalf("expected charlie, got %s", claims2.Subject)
	}
}

func TestJWT_AsymmetricAlgorithms(t *testing.T) {
	ctx := context.Background()

	t.Run("RSA (RS256 and PS256)", func(t *testing.T) {
		rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
		kRS, _ := jwt.NewRSAKey("rsa-rs", jwt.RS256, rsaPriv)
		kPS, _ := jwt.NewRSAKey("rsa-ps", jwt.PS256, rsaPriv)

		_, plugin := setupTestAuth(t, jwt.WithKey(kRS), jwt.WithKey(kPS))

		tokenRS, err := plugin.IssueWithKey(ctx, "rsa-rs", jwt.Claims{Subject: "rsa-user"})
		if err != nil {
			t.Fatalf("issue RS256: %v", err)
		}
		if _, err := plugin.Verify(ctx, tokenRS); err != nil {
			t.Fatalf("verify RS256: %v", err)
		}

		tokenPS, err := plugin.IssueWithKey(ctx, "rsa-ps", jwt.Claims{Subject: "ps-user"})
		if err != nil {
			t.Fatalf("issue PS256: %v", err)
		}
		if _, err := plugin.Verify(ctx, tokenPS); err != nil {
			t.Fatalf("verify PS256: %v", err)
		}
	})

	t.Run("ECDSA (ES256)", func(t *testing.T) {
		ecPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		kEC, _ := jwt.NewECDSAKey("ec-1", jwt.ES256, ecPriv)

		_, plugin := setupTestAuth(t, jwt.WithKey(kEC))

		tokenEC, err := plugin.Issue(ctx, jwt.Claims{Subject: "ec-user"})
		if err != nil {
			t.Fatalf("issue ES256: %v", err)
		}
		if _, err := plugin.Verify(ctx, tokenEC); err != nil {
			t.Fatalf("verify ES256: %v", err)
		}
	})

	t.Run("Ed25519 (EdDSA)", func(t *testing.T) {
		_, edPriv, _ := ed25519.GenerateKey(rand.Reader)
		kEd, _ := jwt.NewEd25519Key("ed-1", edPriv)

		_, plugin := setupTestAuth(t, jwt.WithKey(kEd))

		tokenEd, err := plugin.Issue(ctx, jwt.Claims{Subject: "ed-user"})
		if err != nil {
			t.Fatalf("issue EdDSA: %v", err)
		}
		if _, err := plugin.Verify(ctx, tokenEd); err != nil {
			t.Fatalf("verify EdDSA: %v", err)
		}
	})
}

func TestJWT_Revocation(t *testing.T) {
	k := defaultHMACKey(t, "key-1")

	_, plugin := setupTestAuth(t,
		jwt.WithKey(k),
		jwt.WithDefaultTTL(10*time.Minute),
	)
	ctx := context.Background()

	// 1. Individual token revocation by JTI
	token, err := plugin.Issue(ctx, jwt.Claims{Subject: "user_rev", ID: "jti_rev_1"})
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	// Should verify before revocation
	if _, err := plugin.Verify(ctx, token); err != nil {
		t.Fatalf("verify before revocation failed: %v", err)
	}

	// Revoke token
	if err := plugin.Revoke(ctx, "jti_rev_1", time.Now().Add(10*time.Minute), "user logged out"); err != nil {
		t.Fatalf("revoke failed: %v", err)
	}

	// Should fail verification after revocation
	_, err = plugin.Verify(ctx, token)
	if !errors.Is(err, jwt.ErrTokenRevoked) {
		t.Fatalf("expected ErrTokenRevoked, got %v", err)
	}

	// 2. Blanket subject revocation
	tokenSub, err := plugin.Issue(ctx, jwt.Claims{Subject: "user_blanket"})
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	time.Sleep(5 * time.Millisecond)
	if err := plugin.RevokeSubject(ctx, "user_blanket", time.Now(), "compromised"); err != nil {
		t.Fatalf("revoke subject: %v", err)
	}

	_, err = plugin.Verify(ctx, tokenSub)
	if !errors.Is(err, jwt.ErrTokenRevoked) {
		t.Fatalf("expected ErrTokenRevoked after subject revocation, got %v", err)
	}
}

func TestJWT_HooksAndEvents(t *testing.T) {
	k := defaultHMACKey(t, "key-1")
	hooks := jwt.NewHooks()

	var beforeIssueCalled, afterIssueCalled int32
	var beforeVerifyCalled, afterVerifyCalled int32

	hooks.BeforeIssue(func(ctx context.Context, claims *jwt.Claims) error {
		atomic.AddInt32(&beforeIssueCalled, 1)
		claims.Custom = map[string]any{"hook_injected": "val"}
		return nil
	})
	hooks.AfterIssue(func(ctx context.Context, tokenString string, claims *jwt.Claims) error {
		atomic.AddInt32(&afterIssueCalled, 1)
		return nil
	})
	hooks.BeforeVerify(func(ctx context.Context, tokenString string) error {
		atomic.AddInt32(&beforeVerifyCalled, 1)
		return nil
	})
	hooks.AfterVerify(func(ctx context.Context, claims *jwt.Claims) error {
		atomic.AddInt32(&afterVerifyCalled, 1)
		return nil
	})

	app, plugin := setupTestAuth(t, jwt.WithKey(k), jwt.WithHooks(hooks))
	ctx := context.Background()

	// Track events
	var issuedEvents, verifiedEvents int32
	var mu sync.Mutex
	app.Events().Subscribe(jwt.EventJWTTokenIssued, func(ctx context.Context, e auth.Event) {
		mu.Lock()
		defer mu.Unlock()
		issuedEvents++
	})
	app.Events().Subscribe(jwt.EventJWTTokenVerified, func(ctx context.Context, e auth.Event) {
		mu.Lock()
		defer mu.Unlock()
		verifiedEvents++
	})

	token, err := plugin.Issue(ctx, jwt.Claims{Subject: "hook_user"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	claims, err := plugin.Verify(ctx, token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	if claims.Custom["hook_injected"] != "val" {
		t.Fatalf("expected hook injected custom claim, got %v", claims.Custom)
	}

	if atomic.LoadInt32(&beforeIssueCalled) != 1 || atomic.LoadInt32(&afterIssueCalled) != 1 {
		t.Fatal("issue hooks were not called")
	}
	if atomic.LoadInt32(&beforeVerifyCalled) != 1 || atomic.LoadInt32(&afterVerifyCalled) != 1 {
		t.Fatal("verify hooks were not called")
	}

	mu.Lock()
	defer mu.Unlock()
	if issuedEvents != 1 || verifiedEvents != 1 {
		t.Fatalf("expected 1 issued event and 1 verified event, got %d, %d", issuedEvents, verifiedEvents)
	}
}

func TestJWT_JWKS_Export(t *testing.T) {
	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	kRSA, _ := jwt.NewRSAKey("rsa-jwks", jwt.RS256, rsaPriv)
	kHMAC, _ := jwt.NewHMACKey("hmac-secret", jwt.HS256, []byte("at-least-32-bytes-hmac-secret-xyz!!"))

	_, plugin := setupTestAuth(t, jwt.WithKey(kRSA), jwt.WithKey(kHMAC))
	ctx := context.Background()

	jwks, err := plugin.JWKS(ctx)
	if err != nil {
		t.Fatalf("JWKS failed: %v", err)
	}

	// Must only have the RSA key
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected 1 key in JWKS, got %d", len(jwks.Keys))
	}
	if jwks.Keys[0].Kid != "rsa-jwks" {
		t.Fatalf("expected rsa-jwks, got %s", jwks.Keys[0].Kid)
	}
}
