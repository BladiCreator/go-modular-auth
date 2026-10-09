package jwt

import (
	"context"
	"testing"
	"time"
)

func FuzzParseToken(f *testing.F) {
	seeds := []string{
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
		"eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.",
		"..",
		"...",
		"a.b.c",
		"eyJhbGciOiJSUzI1NiJ9.e30.c2ln",
		"",
		"invalid-token",
		"eyJhbGciOiJIUzI1NiJ9",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, token string) {
		parsed, err := parseToken(token)
		if err == nil && parsed == nil {
			t.Errorf("parseToken returned nil error and nil parsedToken")
		}
	})
}

func FuzzVerifyToken(f *testing.F) {
	keyMgr := NewKeyManager()
	key, err := NewHMACKey("test-key", HS256, []byte("super-secret-key-that-is-at-least-32-bytes-long!"))
	if err != nil {
		f.Fatalf("failed to create HMAC key: %v", err)
	}
	_ = keyMgr.AddKey(key)
	svc := newService(nil, Config{KeyManager: keyMgr, Issuer: "https://issuer.com", Leeway: 5 * time.Second})

	f.Add("eyJhbGciOiJIUzI1NiIsImtpZCI6InRlc3Qta2V5In0.eyJpc3MiOiJodHRwczovL2lzc3Vlci5jb20iLCJzdWIiOiJ1c2VyLTEifQ.invalidsig")
	f.Add("")
	f.Add("not.a.token")

	f.Fuzz(func(t *testing.T, rawToken string) {
		ctx := context.Background()
		_, _ = svc.Verify(ctx, rawToken)
	})
}
