package bearer_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth/adapters/memory"
	"github.com/BladiCreator/go-modular-auth/auth"
	"github.com/BladiCreator/go-modular-auth/config"
	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/plugins"
	"github.com/BladiCreator/go-modular-auth/plugins/bearer"
)

const testSecret = "test-cryptographic-secret-key-32b"

func TestCrypto_SignAndVerify(t *testing.T) {
	t.Run("valid signature verification", func(t *testing.T) {
		rawToken := "session_abc123"
		signed := bearer.SignToken(rawToken, testSecret)

		if signed == rawToken {
			t.Fatalf("expected signed token to differ from raw token")
		}

		verified, err := bearer.VerifyToken(signed, testSecret)
		if err != nil {
			t.Fatalf("unexpected error verifying valid token: %v", err)
		}
		if verified != rawToken {
			t.Fatalf("expected verified token '%s', got '%s'", rawToken, verified)
		}
	})

	t.Run("tampered signature fails verification", func(t *testing.T) {
		rawToken := "session_abc123"
		signed := bearer.SignToken(rawToken, testSecret)
		tampered := signed + "tampered"

		_, err := bearer.VerifyToken(tampered, testSecret)
		if !errors.Is(err, bearer.ErrInvalidSignature) {
			t.Fatalf("expected ErrInvalidSignature, got %v", err)
		}
	})

	t.Run("wrong secret fails verification", func(t *testing.T) {
		rawToken := "session_abc123"
		signed := bearer.SignToken(rawToken, testSecret)

		_, err := bearer.VerifyToken(signed, "wrong-secret-key")
		if !errors.Is(err, bearer.ErrInvalidSignature) {
			t.Fatalf("expected ErrInvalidSignature, got %v", err)
		}
	})

	t.Run("malformed token formats", func(t *testing.T) {
		testCases := []string{
			"",
			"no_dot_in_token",
			".only_dot_after",
			"only_dot_before.",
			"too.many.dots.in.token",
		}
		for _, tc := range testCases {
			_, err := bearer.VerifyToken(tc, testSecret)
			if !errors.Is(err, bearer.ErrInvalidTokenFormat) {
				t.Errorf("expected ErrInvalidTokenFormat for '%s', got %v", tc, err)
			}
		}
	})

	t.Run("empty secret returns error", func(t *testing.T) {
		_, err := bearer.VerifyToken("foo.bar", "")
		if !errors.Is(err, bearer.ErrSecretRequired) {
			t.Fatalf("expected ErrSecretRequired, got %v", err)
		}
	})

	t.Run("TryDecodeToken percent-encoded", func(t *testing.T) {
		encoded := "token%2Esignature%2Bvalue"
		decoded := bearer.TryDecodeToken(encoded)
		expected := "token.signature+value"
		if decoded != expected {
			t.Fatalf("expected '%s', got '%s'", expected, decoded)
		}

		plain := "token.signature"
		if bearer.TryDecodeToken(plain) != plain {
			t.Fatalf("expected plain token to remain unchanged")
		}
	})
}

func TestPlugin_ExtractToken(t *testing.T) {
	p := bearer.New(nil)

	testCases := []struct {
		name        string
		header      string
		expected    string
		expectedErr error
	}{
		{
			name:        "standard bearer header",
			header:      "Bearer my_token_123",
			expected:    "my_token_123",
			expectedErr: nil,
		},
		{
			name:        "lowercase bearer header",
			header:      "bearer my_token_123",
			expected:    "my_token_123",
			expectedErr: nil,
		},
		{
			name:        "uppercase bearer header",
			header:      "BEARER my_token_123",
			expected:    "my_token_123",
			expectedErr: nil,
		},
		{
			name:        "mixed case with extra spaces",
			header:      "  BeArEr   my_token_123  ",
			expected:    "my_token_123",
			expectedErr: nil,
		},
		{
			name:        "empty header",
			header:      "",
			expected:    "",
			expectedErr: bearer.ErrTokenEmpty,
		},
		{
			name:        "missing bearer scheme",
			header:      "Basic dXNlcjpwYXNz",
			expected:    "",
			expectedErr: bearer.ErrInvalidHeader,
		},
		{
			name:        "bearer scheme without token",
			header:      "Bearer ",
			expected:    "",
			expectedErr: bearer.ErrTokenEmpty,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			token, err := p.ExtractToken(tc.header)
			if tc.expectedErr != nil {
				if !errors.Is(err, tc.expectedErr) {
					t.Fatalf("expected error %v, got %v", tc.expectedErr, err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if token != tc.expected {
					t.Fatalf("expected token '%s', got '%s'", tc.expected, token)
				}
			}
		})
	}
}

func TestPlugin_Verify(t *testing.T) {
	ctx := context.Background()

	t.Run("verify signed token successfully", func(t *testing.T) {
		p := bearer.New(nil, bearer.WithSecret(testSecret))
		signed := bearer.SignToken("session_123", testSecret)

		params := bearer.VerifyParams{Token: signed}
		params.Set("client_ip", "127.0.0.1")
		ip, ok := params.Get("client_ip")
		if !ok || ip != "127.0.0.1" {
			t.Fatalf("failed to retrieve extra metadata")
		}

		res, err := p.Verify(ctx, params)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.RawToken != "session_123" {
			t.Fatalf("expected raw token 'session_123', got '%s'", res.RawToken)
		}
		if !res.Valid {
			t.Fatalf("expected valid to be true")
		}
	})

	t.Run("verify raw token when RequireSignature is false", func(t *testing.T) {
		p := bearer.New(nil,
			bearer.WithSecret(testSecret),
			bearer.WithRequireSignature(false),
		)

		res, err := p.Verify(ctx, bearer.VerifyParams{Token: "raw_session_token"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.RawToken != "raw_session_token" {
			t.Fatalf("expected raw token 'raw_session_token', got '%s'", res.RawToken)
		}
		expectedSigned := bearer.SignToken("raw_session_token", testSecret)
		if res.SignedToken != expectedSigned {
			t.Fatalf("expected signed token '%s', got '%s'", expectedSigned, res.SignedToken)
		}
	})

	t.Run("verify raw token when RequireSignature is true returns error", func(t *testing.T) {
		p := bearer.New(nil,
			bearer.WithSecret(testSecret),
			bearer.WithRequireSignature(true),
		)

		_, err := p.Verify(ctx, bearer.VerifyParams{Token: "raw_session_token"})
		if !errors.Is(err, bearer.ErrInvalidTokenFormat) {
			t.Fatalf("expected ErrInvalidTokenFormat, got %v", err)
		}
	})

	t.Run("verify empty token returns error", func(t *testing.T) {
		p := bearer.New(nil, bearer.WithSecret(testSecret))
		_, err := p.Verify(ctx, bearer.VerifyParams{Token: ""})
		if !errors.Is(err, bearer.ErrTokenEmpty) {
			t.Fatalf("expected ErrTokenEmpty, got %v", err)
		}
	})
}

func TestPlugin_CreateToken(t *testing.T) {
	ctx := context.Background()
	p := bearer.New(nil,
		bearer.WithSecret(testSecret),
		bearer.WithAuthTokenHeader("custom-auth-token"),
	)

	params := bearer.CreateTokenParams{
		Token:  "session_token_xyz",
		UserID: "usr_100",
	}
	params.Set("origin", "mobile")
	if v, _ := params.Get("origin"); v != "mobile" {
		t.Fatalf("failed to retrieve extra metadata")
	}

	res, err := p.CreateToken(ctx, params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.RawToken != "session_token_xyz" {
		t.Fatalf("expected raw token 'session_token_xyz', got '%s'", res.RawToken)
	}
	expectedSigned := bearer.SignToken("session_token_xyz", testSecret)
	if res.SignedToken != expectedSigned {
		t.Fatalf("expected signed token '%s', got '%s'", expectedSigned, res.SignedToken)
	}
	expectedHeader := "Bearer " + expectedSigned
	if res.HeaderValue != expectedHeader {
		t.Fatalf("expected header value '%s', got '%s'", expectedHeader, res.HeaderValue)
	}
	if res.AuthTokenHeader != "custom-auth-token" {
		t.Fatalf("expected auth token header 'custom-auth-token', got '%s'", res.AuthTokenHeader)
	}
}

func TestPlugin_ResolveSession(t *testing.T) {
	ctx := context.Background()
	store := memory.New()

	// Seed session
	sess, err := store.CreateSession(ctx, &dto.CreateSessionParams{
		UserID:    "usr_gopher",
		Token:     "raw_token_sess_99",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("failed to seed session: %v", err)
	}

	p := bearer.New(store, bearer.WithSecret(testSecret))

	t.Run("resolve session via Authorization header", func(t *testing.T) {
		signed := bearer.SignToken(sess.Token, testSecret)
		header := "Bearer " + signed

		res, err := p.ResolveSession(ctx, bearer.ResolveSessionParams{
			Header: header,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Session == nil || res.Session.UserID != "usr_gopher" {
			t.Fatalf("expected session for user 'usr_gopher'")
		}
		if res.RawToken != sess.Token {
			t.Fatalf("expected raw token '%s', got '%s'", sess.Token, res.RawToken)
		}
	})

	t.Run("resolve session via direct token", func(t *testing.T) {
		signed := bearer.SignToken(sess.Token, testSecret)
		res, err := p.ResolveSession(ctx, bearer.ResolveSessionParams{
			Token: signed,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Session == nil || res.Session.UserID != "usr_gopher" {
			t.Fatalf("expected session for user 'usr_gopher'")
		}
	})

	t.Run("expired session returns ErrSessionExpired", func(t *testing.T) {
		expiredSess, err := store.CreateSession(ctx, &dto.CreateSessionParams{
			UserID:    "usr_expired",
			Token:     "expired_token_123",
			ExpiresAt: time.Now().Add(-1 * time.Hour),
			CreatedAt: time.Now().Add(-2 * time.Hour),
		})
		if err != nil {
			t.Fatalf("failed to create expired session: %v", err)
		}

		signed := bearer.SignToken(expiredSess.Token, testSecret)
		_, err = p.ResolveSession(ctx, bearer.ResolveSessionParams{
			Token: signed,
		})
		if !errors.Is(err, bearer.ErrSessionExpired) {
			t.Fatalf("expected ErrSessionExpired, got %v", err)
		}
	})
}

func TestPlugin_FullIntegration(t *testing.T) {
	ctx := context.Background()
	store := memory.New()

	var eventTokenCreated string
	var eventVerifySuccess bool

	app, err := auth.New(
		config.WithPlugins(
			plugins.Bearer(
				store,
				bearer.WithSecret(testSecret),
				bearer.WithCustomTokenHeader("X-Auth-Token"),
				bearer.WithCustomAuthTokenHeader("x-set-token"),
			),
		),
	)
	if err != nil {
		t.Fatalf("failed to initialize auth engine: %v", err)
	}

	app.Events().Subscribe(bearer.EventBearerTokenCreated, func(c context.Context, payload *bearer.BearerTokenCreatedEventPayload) {
		eventTokenCreated = payload.SignedToken
	})

	app.Events().Subscribe(bearer.EventBearerVerifyAfter, func(c context.Context, payload *bearer.BearerVerifyAfterEventPayload) {
		eventVerifySuccess = payload.Valid
	})

	bearerP := auth.Plugin[bearer.Plugin](app)
	if bearerP.ID() != "bearer" {
		t.Fatalf("expected plugin ID 'bearer', got '%s'", bearerP.ID())
	}

	// 1. Create Token
	resToken, err := bearerP.CreateToken(ctx, bearer.CreateTokenParams{
		Token: "my_integration_session_token",
	})
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}
	if eventTokenCreated != resToken.SignedToken {
		t.Fatalf("event listener did not receive correct token")
	}

	// 2. Verify Token
	verifyRes, err := bearerP.Verify(ctx, bearer.VerifyParams{
		Token: resToken.SignedToken,
	})
	if err != nil {
		t.Fatalf("failed to verify token: %v", err)
	}
	if !verifyRes.Valid || !eventVerifySuccess {
		t.Fatalf("expected verification to succeed")
	}

	// 3. Format and Header Helpers
	headerVal := bearerP.FormatHeader(resToken.SignedToken)
	if headerVal != "Bearer "+resToken.SignedToken {
		t.Fatalf("unexpected formatted header: %s", headerVal)
	}

	hName, hVal := bearerP.FormatAuthTokenHeader(resToken.SignedToken)
	if hName != "x-set-token" || hVal != resToken.SignedToken {
		t.Fatalf("unexpected auth token header pair: %s=%s", hName, hVal)
	}

	if bearerP.ExposedHeaders() != "x-set-token" {
		t.Fatalf("unexpected exposed headers: %s", bearerP.ExposedHeaders())
	}
}

func BenchmarkSignToken(b *testing.B) {
	token := "session_benchmark_token_123456789"
	secret := "benchmark-secret-key-32-bytes!!"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = bearer.SignToken(token, secret)
	}
}

func BenchmarkVerifyToken(b *testing.B) {
	secret := "benchmark-secret-key-32-bytes!!"
	signed := bearer.SignToken("session_benchmark_token_123456789", secret)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = bearer.VerifyToken(signed, secret)
	}
}
