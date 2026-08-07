package main

import (
	"context"
	"fmt"

	"github.com/BladiCreator/go-modular-auth/adapters/memory"
	"github.com/BladiCreator/go-modular-auth/auth"
	"github.com/BladiCreator/go-modular-auth/config"
	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/plugins"
	"github.com/BladiCreator/go-modular-auth/plugins/emailpassword"
	"github.com/BladiCreator/go-modular-auth/plugins/twofactor"
)

func main() {
	ctx := context.Background()
	repository := memory.New()

	// 1. Clean initialization with developer-friendly DX
	app, err := auth.New(
		config.WithPlugins(
			plugins.EmailPassword(repository),
			plugins.TwoFactor(repository, twofactor.WithIssuer("Go Modular Auth")),
		),
	)
	if err != nil {
		panic(err)
	}

	// 2. Global event subscription using asaskevich/EventBus
	app.Events().Subscribe(emailpassword.EventSignUpAfter, func(c context.Context, payload *emailpassword.SignUpEventPayload) {
		fmt.Printf("📢 [Global EventBus] New user registered!: %s\n", payload.User.Email)
	})

	// 3. User registration via EmailPassword plugin
	user, err := auth.Plugin[emailpassword.Plugin](app).SignUp(ctx, dto.SignUpParams{
		Name:     "Gopher Go",
		Email:    "gopher@golang.org",
		Password: "PasswordSegura123!",
	})
	if err != nil {
		panic(err)
	}
	fmt.Printf("✔ User created: %s (%s)\n", user.Name, user.ID)

	// 4. Sign-in authentication
	signedInUser, err := auth.Plugin[emailpassword.Plugin](app).SignIn(ctx, dto.SignInParams{
		Email:    "gopher@golang.org",
		Password: "PasswordSegura123!",
	})
	if err != nil {
		panic(err)
	}
	fmt.Printf("✔ Session started for: %s (%s)\n", signedInUser.Name, signedInUser.ID)

	// 5. Generate 2FA TOTP Secret
	secretURI, err := auth.Plugin[twofactor.Plugin](app).GenerateTOTPSecret(ctx, user.ID)
	if err != nil {
		panic(err)
	}
	fmt.Printf("✔ 2FA Secret URI: %s\n", secretURI)

	// 6. Verify 2FA TOTP Code
	valid, err := auth.Plugin[twofactor.Plugin](app).VerifyCode(ctx, user.ID, "123456")
	if err != nil {
		panic(err)
	}
	fmt.Printf("✔ 2FA code verified: %v\n", valid)
}
