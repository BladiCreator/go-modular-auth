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

	// 1. Inicialización limpia con la DX solicitada
	app, err := auth.New(
		config.WithPlugins(
			plugins.EmailPassword(repository),
			plugins.TwoFactor(repository, twofactor.WithIssuer("Go Modular Auth")),
		),
	)
	if err != nil {
		panic(err)
	}

	// 2. Suscripción global a eventos usando asaskevich/EventBus
	app.Events().Subscribe(emailpassword.EventSignUpAfter, func(c context.Context, payload *emailpassword.SignUpEventPayload) {
		fmt.Printf("📢 [EventBus Global] ¡Nuevo usuario registrado!: %s\n", payload.User.Email)
	})

	// 3. Registro vía plugin EmailPassword
	user, err := auth.Plugin[emailpassword.Plugin](app).SignUp(ctx, dto.SignUpParams{
		Name:     "Gopher Go",
		Email:    "gopher@golang.org",
		Password: "PasswordSegura123!",
	})
	if err != nil {
		panic(err)
	}
	fmt.Printf("✔ Usuario creado: %s (%s)\n", user.Name, user.ID)

	// 4. Inicio de Sesión
	signedInUser, err := auth.Plugin[emailpassword.Plugin](app).SignIn(ctx, dto.SignInParams{
		Email:    "gopher@golang.org",
		Password: "PasswordSegura123!",
	})
	if err != nil {
		panic(err)
	}
	fmt.Printf("✔ Sesión iniciada para: %s (%s)\n", signedInUser.Name, signedInUser.ID)

	// 5. Generación de Secreto 2FA
	secretURI, err := auth.Plugin[twofactor.Plugin](app).GenerateTOTPSecret(ctx, user.ID)
	if err != nil {
		panic(err)
	}
	fmt.Printf("✔ Secreto 2FA: %s\n", secretURI)

	// 6. Verificación de Código 2FA
	valid, err := auth.Plugin[twofactor.Plugin](app).VerifyCode(ctx, user.ID, "123456")
	if err != nil {
		panic(err)
	}
	fmt.Printf("✔ Código 2FA verificado: %v\n", valid)
}
