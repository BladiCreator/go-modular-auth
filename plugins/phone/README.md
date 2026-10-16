# gomodularauth-phone

`gomodularauth-phone` is an official plugin module for **[GoModularAuth](https://github.com/BladiCreator/go-modular-auth)**. It provides first-class phone-number identity mappings and single-use phone OTP (One-Time Password) authentication through a provider-agnostic server-side interface.

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/phone
```

## Quick Start

```go
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapters/memory"
	phone "github.com/BladiCreator/go-modular-auth/plugins/phone"
	"github.com/BladiCreator/go-modular-auth/plugins/phone/plugins"
)

// Example Twilio or custom SMS provider
type CustomSMSProvider struct{}

func (s *CustomSMSProvider) Send(ctx context.Context, msg phone.Message) error {
	fmt.Printf("[SMS Gateway] Sending SMS to %s: %s\n", msg.To, msg.Body)
	return nil
}

func main() {
	smsProvider := &CustomSMSProvider{}

	// 1. Initialize GoModularAuth engine with the Phone plugin
	engine, err := auth.New(auth.Config{
		Adapter: adaptermem.NewAdapter(),
		Plugins: []auth.PluginModule{
			phone.New(
				phone.WithProvider(smsProvider),
				phone.WithTTL(5*time.Minute),
				phone.WithMaxAttempts(3),
				phone.WithAllowSignUp(true),
			),
		},
	})
	if err != nil {
		log.Fatalf("failed to initialize auth: %v", err)
	}

	// 2. Retrieve the strongly typed Phone capability
	phoneAuth, err := auth.Get[plugins.Phone](engine)
	if err != nil {
		log.Fatalf("failed to get phone capability: %v", err)
	}

	ctx := context.Background()

	// 3. Request an OTP
	err = phoneAuth.RequestOTP(ctx, phone.RequestOTPInput{
		PhoneNumber: "+1 (202) 555-0123",
	})
	if err != nil {
		log.Fatalf("RequestOTP failed: %v", err)
	}

	// 4. Verify the OTP code received by the user
	res, err := phoneAuth.VerifyOTP(ctx, phone.VerifyOTPInput{
		PhoneNumber: "+12025550123",
		Code:        "123456", // code delivered via SMS
	})
	if err != nil {
		log.Fatalf("VerifyOTP failed: %v", err)
	}

	fmt.Printf("Authenticated successfully! User ID: %s, Session Token: %s\n", res.User.ID, res.Token)
}
```

Detailed guide: [**`doc/plugins/phone.md`**](../../doc/plugins/phone.md).
