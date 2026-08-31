package magiclink_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/BladiCreator/go-modular-auth/plugins/magiclink"
)

func BenchmarkSignInMagicLink(b *testing.B) {
	repo := newMockRepository()
	p := magiclink.New(repo,
		magiclink.WithSendMagicLink(func(ctx context.Context, data magiclink.SendMagicLinkData) error {
			return nil
		}),
	)

	ctx := context.Background()

	for i := 0; b.Loop(); i++ {
		email := fmt.Sprintf("user_%d@example.com", i)
		_, _ = p.SignInMagicLink(ctx, magiclink.SignInMagicLinkParams{
			Email: email,
		})
	}
}

func BenchmarkVerifyMagicLink(b *testing.B) {
	repo := newMockRepository()
	var currentToken string

	p := magiclink.New(repo,
		magiclink.WithSendMagicLink(func(ctx context.Context, data magiclink.SendMagicLinkData) error {
			currentToken = data.Token
			return nil
		}),
	)

	ctx := context.Background()

	for i := 0; b.Loop(); i++ {
		b.StopTimer()
		email := fmt.Sprintf("benchuser_%d@example.com", i)
		_, _ = p.SignInMagicLink(ctx, magiclink.SignInMagicLinkParams{
			Email: email,
		})
		b.StartTimer()

		_, _ = p.VerifyMagicLink(ctx, magiclink.VerifyMagicLinkParams{
			Token: currentToken,
			Email: email,
		})
	}
}
