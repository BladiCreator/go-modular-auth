package jwt_test

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth/adapters/memory"
	"github.com/BladiCreator/go-modular-auth/auth"
	"github.com/BladiCreator/go-modular-auth/config"
	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/plugins"
	"github.com/BladiCreator/go-modular-auth/plugins/jwt"
)

const testSecret = "test-cryptographic-secret-key-32b"

func TestCrypto_GenerateKeyPair(t *testing.T) {
	algorithms := []jwt.Algorithm{
		jwt.AlgEdDSA,
		jwt.AlgES256,
		jwt.AlgES512,
		jwt.AlgRS256,
		jwt.AlgPS256,
	}

	for _, alg := range algorithms {
		t.Run(string(alg), func(t *testing.T) {
			record, privKey, err := jwt.GenerateKeyPair(alg, 2048)
			if err != nil {
				t.Fatalf("failed to generate key pair for %s: %v", alg, err)
			}
			if record == nil || privKey == nil {
				t.Fatalf("expected non-nil record and private key")
			}
			if record.Algorithm != alg {
				t.Fatalf("expected algorithm %s, got %s", alg, record.Algorithm)
			}
			if record.PublicKey == "" || record.PrivateKey == "" {
				t.Fatalf("expected non-empty public and private key strings")
			}
		})
	}
}

func TestCrypto_AESGCM_Encryption(t *testing.T) {
	plainText := []byte("super-secret-private-key-bytes-123456789")

	t.Run("encrypt and decrypt successful", func(t *testing.T) {
		encrypted, err := jwt.EncryptPrivateKey(plainText, testSecret)
		if err != nil {
			t.Fatalf("encryption failed: %v", err)
		}
		if encrypted == string(plainText) {
			t.Fatalf("ciphertext must not equal plaintext")
		}

		decrypted, err := jwt.DecryptPrivateKey(encrypted, testSecret)
		if err != nil {
			t.Fatalf("decryption failed: %v", err)
		}
		if string(decrypted) != string(plainText) {
			t.Fatalf("expected '%s', got '%s'", string(plainText), string(decrypted))
		}
	})

	t.Run("wrong secret fails decryption", func(t *testing.T) {
		encrypted, err := jwt.EncryptPrivateKey(plainText, testSecret)
		if err != nil {
			t.Fatalf("encryption failed: %v", err)
		}

		_, err = jwt.DecryptPrivateKey(encrypted, "wrong-secret-key-1234567890123456")
		if !errors.Is(err, jwt.ErrDecryptionFailed) {
			t.Fatalf("expected ErrDecryptionFailed, got %v", err)
		}
	})

	t.Run("tampered ciphertext fails decryption", func(t *testing.T) {
		encrypted, err := jwt.EncryptPrivateKey(plainText, testSecret)
		if err != nil {
			t.Fatalf("encryption failed: %v", err)
		}

		tampered := encrypted + "tamper"
		_, err = jwt.DecryptPrivateKey(tampered, testSecret)
		if !errors.Is(err, jwt.ErrDecryptionFailed) {
			t.Fatalf("expected ErrDecryptionFailed, got %v", err)
		}
	})

	t.Run("empty secret returns ErrSecretRequired", func(t *testing.T) {
		_, err := jwt.EncryptPrivateKey(plainText, "")
		if !errors.Is(err, jwt.ErrSecretRequired) {
			t.Fatalf("expected ErrSecretRequired, got %v", err)
		}

		_, err = jwt.DecryptPrivateKey("some-ciphertext", "")
		if !errors.Is(err, jwt.ErrSecretRequired) {
			t.Fatalf("expected ErrSecretRequired, got %v", err)
		}
	})
}

func TestPlugin_SignAndVerify_Algorithms(t *testing.T) {
	algorithms := []jwt.Algorithm{
		jwt.AlgEdDSA,
		jwt.AlgES256,
		jwt.AlgES512,
		jwt.AlgRS256,
		jwt.AlgPS256,
	}

	for _, alg := range algorithms {
		t.Run(string(alg), func(t *testing.T) {
			store := memory.New()
			p := jwt.New(store,
				jwt.WithAlgorithm(alg),
				jwt.WithSecret(testSecret),
				jwt.WithIssuer("TestIssuer"),
				jwt.WithAudience("api.example.com"),
			)

			if err := p.Init(nil); err != nil {
				t.Fatalf("init failed: %v", err)
			}

			ctx := context.Background()
			signRes, err := p.Sign(ctx, jwt.SignParams{
				Subject: "user_test_123",
				Payload: map[string]any{
					"role":  "admin",
					"email": "user@example.com",
				},
				ExpiresIn: 10 * time.Minute,
			})
			if err != nil {
				t.Fatalf("sign failed: %v", err)
			}

			if signRes.Token == "" || signRes.KeyID == "" {
				t.Fatalf("expected non-empty token and key ID")
			}
			if !strings.HasPrefix(signRes.HeaderValue, "bearer ") {
				t.Fatalf("expected HeaderValue to have bearer prefix")
			}

			// Verify token
			verifyRes, err := p.Verify(ctx, jwt.VerifyParams{
				Token: signRes.Token,
			})
			if err != nil {
				t.Fatalf("verify failed: %v", err)
			}

			if !verifyRes.Valid {
				t.Fatalf("expected token to be valid")
			}
			if verifyRes.Subject != "user_test_123" {
				t.Fatalf("expected subject 'user_test_123', got '%s'", verifyRes.Subject)
			}
			if verifyRes.Claims["role"] != "admin" {
				t.Fatalf("expected role claim 'admin', got '%v'", verifyRes.Claims["role"])
			}
			if verifyRes.Algorithm != alg {
				t.Fatalf("expected algorithm %s, got %s", alg, verifyRes.Algorithm)
			}
			if verifyRes.ExpiresAt == nil {
				t.Fatalf("expected parsed expiresAt timestamp")
			}
		})
	}
}

func TestPlugin_Verify_ValidationsAndErrors(t *testing.T) {
	store := memory.New()
	p := jwt.New(store,
		jwt.WithSecret(testSecret),
		jwt.WithIssuer("AuthService"),
		jwt.WithAudience("my-api"),
		jwt.WithClockSkewLeeway(5*time.Second),
	)
	_ = p.Init(nil)
	ctx := context.Background()

	t.Run("expired token returns ErrTokenExpired", func(t *testing.T) {
		signRes, err := p.Sign(ctx, jwt.SignParams{
			Subject:   "user_exp",
			ExpiresIn: -5 * time.Minute,
		})
		if err != nil {
			t.Fatalf("sign failed: %v", err)
		}

		_, err = p.Verify(ctx, jwt.VerifyParams{
			Token: signRes.Token,
		})
		if !errors.Is(err, jwt.ErrTokenExpired) {
			t.Fatalf("expected ErrTokenExpired, got %v", err)
		}
	})

	t.Run("nbf in future returns ErrTokenNotValidYet", func(t *testing.T) {
		future := time.Now().Add(10 * time.Minute)
		signRes, err := p.Sign(ctx, jwt.SignParams{
			Subject:   "user_nbf",
			NotBefore: &future,
		})
		if err != nil {
			t.Fatalf("sign failed: %v", err)
		}

		_, err = p.Verify(ctx, jwt.VerifyParams{
			Token: signRes.Token,
		})
		if !errors.Is(err, jwt.ErrTokenNotValidYet) {
			t.Fatalf("expected ErrTokenNotValidYet, got %v", err)
		}
	})

	t.Run("tampered payload fails with ErrInvalidSignature", func(t *testing.T) {
		signRes, err := p.Sign(ctx, jwt.SignParams{Subject: "user_tamper"})
		if err != nil {
			t.Fatalf("sign failed: %v", err)
		}

		parts := strings.Split(signRes.Token, ".")
		tamperedPayload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"attacker"}`))
		tamperedToken := parts[0] + "." + tamperedPayload + "." + parts[2]

		_, err = p.Verify(ctx, jwt.VerifyParams{
			Token: tamperedToken,
		})
		if !errors.Is(err, jwt.ErrInvalidSignature) {
			t.Fatalf("expected ErrInvalidSignature, got %v", err)
		}
	})

	t.Run("tampered signature fails with ErrInvalidSignature", func(t *testing.T) {
		signRes, err := p.Sign(ctx, jwt.SignParams{Subject: "user_tamper_sig"})
		if err != nil {
			t.Fatalf("sign failed: %v", err)
		}

		parts := strings.Split(signRes.Token, ".")
		tamperedToken := parts[0] + "." + parts[1] + "." + parts[2] + "abc"

		_, err = p.Verify(ctx, jwt.VerifyParams{
			Token: tamperedToken,
		})
		if !errors.Is(err, jwt.ErrInvalidSignature) {
			t.Fatalf("expected ErrInvalidSignature, got %v", err)
		}
	})

	t.Run("wrong issuer returns ErrInvalidToken", func(t *testing.T) {
		signRes, err := p.Sign(ctx, jwt.SignParams{
			Subject: "user_iss",
			Issuer:  "WrongIssuer",
		})
		if err != nil {
			t.Fatalf("sign failed: %v", err)
		}

		_, err = p.Verify(ctx, jwt.VerifyParams{
			Token: signRes.Token,
		})
		if !errors.Is(err, jwt.ErrInvalidToken) {
			t.Fatalf("expected ErrInvalidToken, got %v", err)
		}
	})

	t.Run("wrong audience returns ErrInvalidToken", func(t *testing.T) {
		signRes, err := p.Sign(ctx, jwt.SignParams{
			Subject:  "user_aud",
			Audience: []string{"other-api"},
		})
		if err != nil {
			t.Fatalf("sign failed: %v", err)
		}

		_, err = p.Verify(ctx, jwt.VerifyParams{
			Token: signRes.Token,
		})
		if !errors.Is(err, jwt.ErrInvalidToken) {
			t.Fatalf("expected ErrInvalidToken, got %v", err)
		}
	})

	t.Run("bearer prefix stripped automatically", func(t *testing.T) {
		signRes, err := p.Sign(ctx, jwt.SignParams{Subject: "user_bearer_prefix"})
		if err != nil {
			t.Fatalf("sign failed: %v", err)
		}

		authHeader := "Bearer " + signRes.Token
		res, err := p.Verify(ctx, jwt.VerifyParams{
			Token: authHeader,
		})
		if err != nil {
			t.Fatalf("unexpected error verifying bearer header: %v", err)
		}
		if res.Subject != "user_bearer_prefix" {
			t.Fatalf("expected subject 'user_bearer_prefix', got '%s'", res.Subject)
		}
	})
}

func TestPlugin_GetToken(t *testing.T) {
	store := memory.New()
	p := jwt.New(store,
		jwt.WithSecret(testSecret),
		jwt.WithDefinePayload(func(session *entity.Session, user *entity.User) (map[string]any, error) {
			return map[string]any{
				"custom_tenant": "tenant_xyz",
				"user_name":     user.Name,
			}, nil
		}),
		jwt.WithGetSubject(func(session *entity.Session, user *entity.User) (string, error) {
			return "sub:" + user.ID, nil
		}),
	)
	_ = p.Init(nil)
	ctx := context.Background()

	sess := &entity.Session{
		ID:        "sess_100",
		UserID:    "user_200",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	usr := &entity.User{
		ID:    "user_200",
		Name:  "Alice",
		Email: "alice@example.com",
	}

	t.Run("generate token successfully with custom payload", func(t *testing.T) {
		res, err := p.GetToken(ctx, jwt.GetTokenParams{
			Session: sess,
			User:    usr,
		})
		if err != nil {
			t.Fatalf("GetToken failed: %v", err)
		}

		if res.Token == "" {
			t.Fatalf("expected non-empty token")
		}

		verifyRes, err := p.Verify(ctx, jwt.VerifyParams{Token: res.Token})
		if err != nil {
			t.Fatalf("verify failed: %v", err)
		}

		if verifyRes.Subject != "sub:user_200" {
			t.Fatalf("expected custom subject 'sub:user_200', got '%s'", verifyRes.Subject)
		}
		if verifyRes.Claims["custom_tenant"] != "tenant_xyz" {
			t.Fatalf("expected custom_tenant claim 'tenant_xyz', got '%v'", verifyRes.Claims["custom_tenant"])
		}
		if verifyRes.Claims["email"] != "alice@example.com" {
			t.Fatalf("expected email claim 'alice@example.com', got '%v'", verifyRes.Claims["email"])
		}
		if verifyRes.Claims["session_id"] != "sess_100" {
			t.Fatalf("expected session_id 'sess_100', got '%v'", verifyRes.Claims["session_id"])
		}
	})

	t.Run("missing session returns ErrSessionNotFound", func(t *testing.T) {
		_, err := p.GetToken(ctx, jwt.GetTokenParams{
			Session: nil,
		})
		if !errors.Is(err, jwt.ErrSessionNotFound) {
			t.Fatalf("expected ErrSessionNotFound, got %v", err)
		}
	})

	t.Run("expired session returns ErrSessionExpired", func(t *testing.T) {
		expiredSess := &entity.Session{
			ID:        "sess_expired",
			UserID:    "user_200",
			ExpiresAt: time.Now().Add(-1 * time.Hour),
		}
		_, err := p.GetToken(ctx, jwt.GetTokenParams{
			Session: expiredSess,
		})
		if !errors.Is(err, jwt.ErrSessionExpired) {
			t.Fatalf("expected ErrSessionExpired, got %v", err)
		}
	})
}

func TestPlugin_GetJWKS(t *testing.T) {
	store := memory.New()
	p := jwt.New(store,
		jwt.WithSecret(testSecret),
		jwt.WithGracePeriod(30*24*time.Hour),
	)
	_ = p.Init(nil)
	ctx := context.Background()

	jwksRes, err := p.GetJWKS(ctx, jwt.GetJWKSParams{})
	if err != nil {
		t.Fatalf("GetJWKS failed: %v", err)
	}

	if jwksRes.KeysCount != 1 {
		t.Fatalf("expected 1 initial key, got %d", jwksRes.KeysCount)
	}

	key := jwksRes.JWKS.Keys[0]
	if key.Kty != "OKP" || key.Alg != "EdDSA" || key.Crv != "Ed25519" || key.X == "" {
		t.Fatalf("invalid public JWK structure: %+v", key)
	}
}

func TestPlugin_KeyRotation(t *testing.T) {
	store := memory.New()
	p := jwt.New(store,
		jwt.WithSecret(testSecret),
		jwt.WithAlgorithm(jwt.AlgEdDSA),
	)
	_ = p.Init(nil)
	ctx := context.Background()

	// 1. Sign token with initial key
	token1, err := p.Sign(ctx, jwt.SignParams{Subject: "user_pre_rotation"})
	if err != nil {
		t.Fatalf("sign 1 failed: %v", err)
	}

	// 2. Rotate keys to ES256
	rotRes, err := p.RotateKeys(ctx, jwt.RotateKeysParams{
		Algorithm: jwt.AlgES256,
	})
	if err != nil {
		t.Fatalf("rotation failed: %v", err)
	}

	if rotRes.NewKey.Algorithm != jwt.AlgES256 {
		t.Fatalf("expected rotated algorithm ES256, got %s", rotRes.NewKey.Algorithm)
	}
	if rotRes.OldKeyID == "" {
		t.Fatalf("expected non-empty OldKeyID")
	}

	// 3. Sign token with new key
	token2, err := p.Sign(ctx, jwt.SignParams{Subject: "user_post_rotation"})
	if err != nil {
		t.Fatalf("sign 2 failed: %v", err)
	}

	// 4. Verify token1 (signed with old key, should still verify via repository)
	res1, err := p.Verify(ctx, jwt.VerifyParams{Token: token1.Token})
	if err != nil {
		t.Fatalf("verifying pre-rotation token failed: %v", err)
	}
	if res1.Subject != "user_pre_rotation" || res1.Algorithm != jwt.AlgEdDSA {
		t.Fatalf("invalid verification of pre-rotation token: %+v", res1)
	}

	// 5. Verify token2 (signed with new key)
	res2, err := p.Verify(ctx, jwt.VerifyParams{Token: token2.Token})
	if err != nil {
		t.Fatalf("verifying post-rotation token failed: %v", err)
	}
	if res2.Subject != "user_post_rotation" || res2.Algorithm != jwt.AlgES256 {
		t.Fatalf("invalid verification of post-rotation token: %+v", res2)
	}

	// 6. Check JWKS contains both keys
	jwksRes, err := p.GetJWKS(ctx, jwt.GetJWKSParams{})
	if err != nil {
		t.Fatalf("GetJWKS failed: %v", err)
	}
	if jwksRes.KeysCount != 2 {
		t.Fatalf("expected 2 keys in JWKS after rotation, got %d", jwksRes.KeysCount)
	}
}

func TestPlugin_AuthEngineIntegrationAndEvents(t *testing.T) {
	store := memory.New()
	jwtPlugin := plugins.JWT(store,
		jwt.WithSecret(testSecret),
		jwt.WithAlgorithm(jwt.AlgEdDSA),
	)

	app, err := auth.New(
		config.WithPlugins(jwtPlugin),
	)
	if err != nil {
		t.Fatalf("failed to create Auth engine: %v", err)
	}

	var eventsCaptured []string
	var mu sync.Mutex

	app.Events().Subscribe(jwt.EventJWTSignBefore, func(ctx context.Context, p *jwt.JWTSignBeforeEventPayload) {
		mu.Lock()
		eventsCaptured = append(eventsCaptured, jwt.EventJWTSignBefore)
		mu.Unlock()
	})

	app.Events().Subscribe(jwt.EventJWTSignAfter, func(ctx context.Context, p *jwt.JWTSignAfterEventPayload) {
		mu.Lock()
		eventsCaptured = append(eventsCaptured, jwt.EventJWTSignAfter)
		mu.Unlock()
	})

	app.Events().Subscribe(jwt.EventJWTVerifyAfter, func(ctx context.Context, p *jwt.JWTVerifyAfterEventPayload) {
		mu.Lock()
		eventsCaptured = append(eventsCaptured, jwt.EventJWTVerifyAfter)
		mu.Unlock()
	})

	app.Events().Subscribe(jwt.EventJWTIssued, func(ctx context.Context, p *jwt.JWTIssuedEventPayload) {
		mu.Lock()
		eventsCaptured = append(eventsCaptured, jwt.EventJWTIssued)
		mu.Unlock()
	})

	p := auth.Plugin[jwt.Plugin](app)
	ctx := context.Background()

	sess, _ := store.CreateSession(ctx, &dto.CreateSessionParams{
		UserID:    "user_integration",
		Token:     "raw_session_token_123",
		ExpiresAt: time.Now().Add(2 * time.Hour),
	})

	tokenRes, err := p.GetToken(ctx, jwt.GetTokenParams{
		Session: sess,
	})
	if err != nil {
		t.Fatalf("GetToken failed: %v", err)
	}

	_, err = p.Verify(ctx, jwt.VerifyParams{
		Token: tokenRes.Token,
	})
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	expectedEvents := []string{
		jwt.EventJWTSignBefore,
		jwt.EventJWTSignAfter,
		jwt.EventJWTIssued,
		jwt.EventJWTVerifyAfter,
	}

	for _, exp := range expectedEvents {
		found := false
		for _, capEv := range eventsCaptured {
			if capEv == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected event %s to be fired, captured: %v", exp, eventsCaptured)
		}
	}
}

func BenchmarkPlugin_SignAndVerify(b *testing.B) {
	store := memory.New()
	p := jwt.New(store,
		jwt.WithSecret(testSecret),
		jwt.WithAlgorithm(jwt.AlgEdDSA),
	)
	_ = p.Init(nil)
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	b.Run("Sign-EdDSA", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = p.Sign(ctx, jwt.SignParams{
				Subject: "benchmark_user",
				Payload: map[string]any{"role": "user", "scope": "read:write"},
			})
		}
	})

	signRes, _ := p.Sign(ctx, jwt.SignParams{
		Subject: "benchmark_user",
		Payload: map[string]any{"role": "user", "scope": "read:write"},
	})

	b.Run("Verify-EdDSA", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = p.Verify(ctx, jwt.VerifyParams{
				Token: signRes.Token,
			})
		}
	})
}
