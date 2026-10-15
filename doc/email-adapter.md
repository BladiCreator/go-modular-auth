# Email Adapter (Transactional Messaging)

## 1. Principles of the Email Adapter

GoModularAuth decouples notification generation from physical network transport.

- **Domain Isolation**: Core workflows (sign-up verification, password resets) and plugins (magic links, email OTPs) determine **what** content to send.
- **Physical Transport Decoupling**: The email adapter handles **how** the message is physically routed and delivered over the wire.
- **Optional**: If email features are disabled or omitted in configuration, the engine operates without an email sender.

---

## 2. Contracts: `email.Sender` & `email.Message`

```go
package email

// Message represents a transactional notification.
type Message struct {
    To      string
    Subject string
    Text    string
    HTML    string
}

// Sender delivers email messages.
type Sender interface {
    Send(ctx context.Context, message Message) error
}

// SenderFunc adapts a closure into an email.Sender.
type SenderFunc func(ctx context.Context, message Message) error

func (f SenderFunc) Send(ctx context.Context, message Message) error {
    return f(ctx, message)
}
```

---

## 3. Official Email Adapters

### 3.1 Production SMTP Adapter (`adapters/smtp`)
GoModularAuth includes a full-featured SMTP adapter supporting TLS, STARTTLS, PLAIN authentication, and multipart/alternative MIME formatting:

```go
package main

import (
    "log"

    auth "github.com/BladiCreator/go-modular-auth"
    adaptermem "github.com/BladiCreator/go-modular-auth/adapters/memory"
    "github.com/BladiCreator/go-modular-auth/adapters/smtp"
)

func main() {
    // 1. Initialize SMTP Sender
    mailer, err := smtp.New(smtp.Config{
        Host:     "smtp.mailgun.org",
        Port:     587,
        Username: "postmaster@my-domain.com",
        Password: "smtp-secret-password",
        From:     "noreply@my-domain.com",
        UseTLS:   false, // STARTTLS automatically used on port 587
    })
    if err != nil {
        log.Fatalf("failed to configure SMTP adapter: %v", err)
    }

    // 2. Attach to engine
    engine, err := auth.New(auth.Config{
        Adapter: adaptermem.NewAdapter(),
        Email:   mailer,
        EmailVerification: auth.EmailVerificationConfig{
            Required:      true,
            SendOnSignUp:  true,
        },
    })
    if err != nil {
        log.Fatal(err)
    }

    _ = engine
}
```

### 3.2 In-Memory Mock Adapter (`adapters/memory`)
Useful for integration tests to assert that emails were generated and sent:

```go
import (
    "github.com/BladiCreator/go-modular-auth/adapters/memory"
)

emailMock := memory.NewEmail()
```
