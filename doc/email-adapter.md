# Email Adapter (Transactional Messaging)

## 1. Principles of the Email Adapter

Email transmission is decoupled from core authentication workflows:

- **Core decides WHAT to send**: Verification links, password reset codes, magic link tokens.
- **Adapter decides HOW to send**: Physical delivery via SMTP, AWS SES, SendGrid, Postmark, Mailgun, or webhooks.
- **Optional**: If email features are not used (or are handled out-of-band by mobile SMS/Push), `Config.Email` may be omitted (`nil`).

---

## 2. The `email.Sender` Contract

```go
type Message struct {
    To      string
    Subject string
    Text    string
    HTML    string
}

type Sender interface {
    Send(ctx context.Context, message Message) error
}

type SenderFunc func(ctx context.Context, message Message) error

func (f SenderFunc) Send(ctx context.Context, message Message) error { 
    return f(ctx, message) 
}
```

---

## 3. Customizing Email Messages

You can customize the format and content of emails dispatched by the core through `Config.Messages`:

```go
app, err := auth.New(auth.Config{
    Store: store,
    Email: emailSender,
    Messages: auth.Messages{
        EmailVerification: func(u *user.User, token string) email.Message {
            return email.Message{
                Subject: "Welcome! Confirm your email",
                Text:    fmt.Sprintf("Click here to confirm: https://myapp.com/verify?token=%s", token),
                HTML:    fmt.Sprintf("<p>Click <a href=\"https://myapp.com/verify?token=%s\">here</a> to confirm.</p>", token),
            }
        },
        PasswordReset: func(u *user.User, token string) email.Message {
            return email.Message{
                Subject: "Password Reset Request",
                Text:    fmt.Sprintf("Use this link to reset your password: https://myapp.com/reset?token=%s", token),
            }
        },
    },
})
```

---

## 4. In-Memory Mock (`email/memory`)

For testing, GoModularAuth provides `email/memory`:

```go
import mememail "github.com/BladiCreator/go-modular-auth/email/memory"

mailer := mememail.New()

// After running an operation:
messages := mailer.Messages()
lastMsg, ok := mailer.Last()
```
Records all dispatched messages thread-safely for assertions.
