package jwt_test

import (
	"context"
	"testing"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapter/memory"
	jwt "github.com/BladiCreator/go-modular-auth/plugins/jwt"
	"github.com/BladiCreator/go-modular-auth/plugins/jwt/plugins"
)

func BenchmarkJWT_IssueHS256(b *testing.B) {
	k, err := jwt.NewHMACKey("key-1", jwt.HS256, []byte("super-secret-key-at-least-32-bytes-long!"))
	if err != nil {
		b.Fatal(err)
	}

	app, err := auth.New(auth.Config{
		Adapter: adaptermem.New(),
		Plugins: []auth.PluginModule{
			jwt.New(
				jwt.WithKey(k),
				jwt.WithIssuer("https://auth.example.com"),
				jwt.WithDefaultAudience("https://api.example.com"),
				jwt.WithDefaultTTL(time.Hour),
			),
		},
	})
	if err != nil {
		b.Fatal(err)
	}

	p, err := auth.Get[plugins.JWT](app)
	if err != nil {
		b.Fatal(err)
	}

	ctx := context.Background()
	claims := jwt.Claims{
		Subject: "usr_42",
		Custom: map[string]any{
			"role": "admin",
		},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		tok, err := p.Issue(ctx, claims)
		if err != nil {
			b.Fatal(err)
		}
		_ = tok
	}
}

func BenchmarkJWT_VerifyHS256(b *testing.B) {
	k, err := jwt.NewHMACKey("key-1", jwt.HS256, []byte("super-secret-key-at-least-32-bytes-long!"))
	if err != nil {
		b.Fatal(err)
	}

	app, err := auth.New(auth.Config{
		Adapter: adaptermem.New(),
		Plugins: []auth.PluginModule{
			jwt.New(
				jwt.WithKey(k),
				jwt.WithIssuer("https://auth.example.com"),
				jwt.WithDefaultAudience("https://api.example.com"),
				jwt.WithDefaultTTL(time.Hour),
			),
		},
	})
	if err != nil {
		b.Fatal(err)
	}

	p, err := auth.Get[plugins.JWT](app)
	if err != nil {
		b.Fatal(err)
	}

	ctx := context.Background()
	claims := jwt.Claims{
		Subject: "usr_42",
		Custom: map[string]any{
			"role": "admin",
		},
	}

	tok, err := p.Issue(ctx, claims)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		c, err := p.Verify(ctx, tok,
			jwt.WithExpectedIssuer("https://auth.example.com"),
			jwt.WithExpectedAudience("https://api.example.com"),
			jwt.WithExpectedSubject("usr_42"),
		)
		if err != nil {
			b.Fatal(err)
		}
		_ = c
	}
}
