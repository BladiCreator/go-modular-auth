# gomodularauth-email-otp

A production-ready, passwordless authentication plugin for **GoModularAuth** providing short-lived, single-use email One-Time Password (OTP) verification codes.

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/email-otp
```

## Quick Start

```go
package main

import (
	"context"
	"log"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapters/memory"
	emailotp "github.com/BladiCreator/go-modular-auth/plugins/email-otp"
	"github.com/BladiCreator/go-modular-auth/plugins/email-otp/plugins"
)

func main() {
	ctx := context.Background()

	// Initialize GoModularAuth with Email OTP plugin
	engine, err := auth.New(auth.Config{
		Adapter: adaptermem.NewAdapter(),
		Email:   adaptermem.NewEmail(),
		Plugins: []auth.PluginModule{
			emailotp.New(
				emailotp.WithOTPLength(6),
				emailotp.WithTTL(10 * time.Minute),
				emailotp.WithMaxAttempts(3),
				emailotp.WithAllowSignUp(true),
			),
		},
	})
	if err != nil {
		log.Fatalf("failed to initialize auth: %v", err)
	}

	// Retrieve typed Capability via GoModularAuth
	otpAuth, err := auth.Get[plugins.EmailOTP](engine)
	if err != nil {
		log.Fatalf("failed to resolve capability: %v", err)
	}

	// 1. Request OTP
	err = otpAuth.Request(ctx, emailotp.RequestInput{
		Email: "user@example.com",
	})
	if err != nil {
		log.Fatalf("request failed: %v", err)
	}

	// 2. Verify OTP (code delivered to user's inbox)
	result, err := otpAuth.Verify(ctx, emailotp.VerifyInput{
		Email: "user@example.com",
		Code:  "123456",
	})
	if err != nil {
		log.Fatalf("verification failed: %v", err)
	}

	log.Printf("Authenticated user ID: %s, Session ID: %s", result.User.ID, result.Session.ID)
}
```

Detailed guide: [**`doc/plugins/email-otp.md`**](../../doc/plugins/email-otp.md).
