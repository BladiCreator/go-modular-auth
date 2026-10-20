package auth_test

import (
	"context"
	"fmt"
	"log"

	auth "github.com/BladiCreator/go-modular-auth"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapter/memory"
)

func ExampleNew() {
	app, err := auth.New(auth.Config{
		Adapter: adaptermem.New(),
	})
	if err != nil {
		log.Fatalf("failed to initialize auth: %v", err)
	}

	fmt.Println(app != nil)
	// Output:
	// true
}

func ExampleAuth_SignUp() {
	ctx := context.Background()
	app, err := auth.New(auth.Config{
		Adapter: adaptermem.New(),
	})
	if err != nil {
		log.Fatalf("init error: %v", err)
	}

	res, err := app.SignUp(ctx, auth.SignUpInput{
		Email:    "newuser@example.com",
		Password: "Password123!",
	})
	if err != nil {
		log.Fatalf("signup error: %v", err)
	}

	fmt.Println(res.User.Email)
	// Output:
	// newuser@example.com
}

func ExampleAuth_SignIn() {
	ctx := context.Background()
	app, err := auth.New(auth.Config{
		Adapter: adaptermem.New(),
	})
	if err != nil {
		log.Fatalf("init error: %v", err)
	}

	_, err = app.SignUp(ctx, auth.SignUpInput{
		Email:    "loginuser@example.com",
		Password: "Password123!",
	})
	if err != nil {
		log.Fatalf("signup error: %v", err)
	}

	signInRes, err := app.SignIn(ctx, auth.SignInInput{
		Email:    "loginuser@example.com",
		Password: "Password123!",
	})
	if err != nil {
		log.Fatalf("signin error: %v", err)
	}

	fmt.Println(signInRes.Session != nil)
	// Output:
	// true
}
