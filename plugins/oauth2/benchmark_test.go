package oauth2_test

import (
	"context"
	"testing"

	"github.com/BladiCreator/go-modular-auth/adapters/memory"
	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/plugin"
	"github.com/BladiCreator/go-modular-auth/plugins/oauth2"
	"github.com/asaskevich/EventBus"
)

func BenchmarkOAuth2_ComputeCodeChallenge(b *testing.B) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = oauth2.ComputeCodeChallenge(verifier)
	}
}

func BenchmarkOAuth2_VerifyPKCE(b *testing.B) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := oauth2.ComputeCodeChallenge(verifier)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = oauth2.VerifyPKCE(verifier, challenge, "S256")
	}
}

func BenchmarkOAuth2_DerivePairwiseSubject(b *testing.B) {
	salt := "secret-salt-pairwise-32-bytes"
	sector := "https://client.example.com"
	userID := "user-123456789"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = oauth2.DerivePairwiseSubject(salt, sector, userID)
	}
}

func BenchmarkOAuth2_AES_EncryptDecrypt(b *testing.B) {
	key := oauth2.DeriveAESKey("my-super-secret-key-32-bytes!!")
	plaintext := []byte("confidential-token-or-secret-string-123456")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		enc, err := oauth2.Encrypt(plaintext, key)
		if err != nil {
			b.Fatal(err)
		}
		_, err = oauth2.Decrypt(enc, key)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOAuth2_TokenIssuance_JWT(b *testing.B) {
	store := memory.New()
	bus := EventBus.New()
	pCtx := plugin.NewContext(&mockCrypto{}, bus)

	p := oauth2.New(store,
		oauth2.WithIssuer("https://auth.example.com"),
		oauth2.WithAccessTokenType(oauth2.AccessTokenTypeJWT),
	)
	_ = p.Init(pCtx)

	user, _ := store.CreateUser(context.Background(), &dto.CreateUserParams{
		Name:  "Bench User",
		Email: "bench@example.com",
	})
	regRes, _ := p.RegisterClient(context.Background(), oauth2.RegisterClientParams{
		ClientName:   "Bench Client",
		RedirectURIs: []string{"https://bench.example.com/callback"},
		Scope:        "openid profile email offline_access",
		SkipConsent:  true,
	})
	client := regRes.Client

	verifier := "bench-verifier-123456789012345678901234"
	challenge := oauth2.ComputeCodeChallenge(verifier)

	ctx := context.Background()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		authRes, _ := p.Authorize(ctx, oauth2.AuthorizeParams{
			ClientID:            client.ClientID,
			RedirectURI:         "https://bench.example.com/callback",
			ResponseType:        "code",
			CodeChallenge:       challenge,
			CodeChallengeMethod: "S256",
			Scope:               "openid profile email offline_access",
			UserID:              user.ID,
		})
		b.StartTimer()

		_, err := p.Token(ctx, oauth2.TokenParams{
			GrantType:    "authorization_code",
			Code:         authRes.Code,
			CodeVerifier: verifier,
			ClientID:     client.ClientID,
			ClientSecret: regRes.ClientSecret,
			RedirectURI:  "https://bench.example.com/callback",
		})
		if err != nil {
			b.Fatalf("token issuance failed: %v", err)
		}
	}
}
