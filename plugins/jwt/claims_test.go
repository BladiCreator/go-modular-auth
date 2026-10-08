package jwt

import (
	"encoding/json"
	"testing"
	"time"
)

func TestClaims_Validation(t *testing.T) {
	now := time.Now().Truncate(time.Second)

	t.Run("Valid claims", func(t *testing.T) {
		claims := Claims{
			Issuer:    "auth.example.com",
			Subject:   "user_123",
			Audience:  Audience{"api.example.com"},
			ExpiresAt: NewNumericDate(now.Add(15 * time.Minute)),
			NotBefore: NewNumericDate(now.Add(-5 * time.Minute)),
			IssuedAt:  NewNumericDate(now),
			ID:        "jti-1",
		}

		cfg := &verifyConfig{
			expectedIssuer:   "auth.example.com",
			expectedAudience: "api.example.com",
			expectedSubject:  "user_123",
			leeway:           time.Minute,
			requiredClaims:   []string{"iss", "sub", "exp", "jti"},
		}

		if err := claims.Validate(now, cfg); err != nil {
			t.Fatalf("unexpected validation error: %v", err)
		}
	})

	t.Run("Expired token without leeway", func(t *testing.T) {
		claims := Claims{
			ExpiresAt: NewNumericDate(now.Add(-5 * time.Second)),
		}
		cfg := &verifyConfig{leeway: 0}
		if err := claims.Validate(now, cfg); err != ErrTokenExpired {
			t.Fatalf("expected ErrTokenExpired, got %v", err)
		}
	})

	t.Run("Expired token saved by leeway", func(t *testing.T) {
		claims := Claims{
			ExpiresAt: NewNumericDate(now.Add(-30 * time.Second)),
		}
		cfg := &verifyConfig{leeway: time.Minute}
		if err := claims.Validate(now, cfg); err != nil {
			t.Fatalf("expected validation success with leeway, got %v", err)
		}
	})

	t.Run("Not yet valid token", func(t *testing.T) {
		claims := Claims{
			NotBefore: NewNumericDate(now.Add(5 * time.Minute)),
		}
		cfg := &verifyConfig{leeway: 0}
		if err := claims.Validate(now, cfg); err != ErrTokenNotYetValid {
			t.Fatalf("expected ErrTokenNotYetValid, got %v", err)
		}
	})

	t.Run("Issuer mismatch", func(t *testing.T) {
		claims := Claims{Issuer: "wrong.com"}
		cfg := &verifyConfig{expectedIssuer: "expected.com"}
		if err := claims.Validate(now, cfg); err != ErrInvalidIssuer {
			t.Fatalf("expected ErrInvalidIssuer, got %v", err)
		}
	})

	t.Run("Audience mismatch", func(t *testing.T) {
		claims := Claims{Audience: Audience{"api1"}}
		cfg := &verifyConfig{expectedAudience: "api2"}
		if err := claims.Validate(now, cfg); err != ErrInvalidAudience {
			t.Fatalf("expected ErrInvalidAudience, got %v", err)
		}
	})

	t.Run("Subject mismatch", func(t *testing.T) {
		claims := Claims{Subject: "user_a"}
		cfg := &verifyConfig{expectedSubject: "user_b"}
		if err := claims.Validate(now, cfg); err != ErrInvalidSubject {
			t.Fatalf("expected ErrInvalidSubject, got %v", err)
		}
	})
}

func TestClaims_Serialization(t *testing.T) {
	claims := Claims{
		Issuer:   "auth",
		Subject:  "usr",
		Audience: Audience{"aud1", "aud2"},
		Custom: map[string]any{
			"role":  "admin",
			"tier":  "enterprise",
			"count": float64(42),
		},
	}

	b, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}

	var parsed Claims
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}

	if parsed.Issuer != "auth" || parsed.Subject != "usr" {
		t.Fatalf("standard claims altered: %+v", parsed)
	}
	if len(parsed.Audience) != 2 || !parsed.Audience.Contains("aud1") {
		t.Fatalf("audience altered: %+v", parsed.Audience)
	}
	if parsed.Custom["role"] != "admin" || parsed.Custom["tier"] != "enterprise" {
		t.Fatalf("custom claims altered: %+v", parsed.Custom)
	}
}
