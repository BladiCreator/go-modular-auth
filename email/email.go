// Package email defines the Email Adapter contract. The core and plugins
// decide WHAT to send (verification, password reset, magic link); adapters
// (SMTP, SES, SendGrid, Postmark, ...) decide HOW it is physically delivered.
package email

import "context"

// Message is a transactional email.
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

// SenderFunc adapts a function into a Sender.
type SenderFunc func(ctx context.Context, message Message) error

// Send calls f(ctx, message).
func (f SenderFunc) Send(ctx context.Context, message Message) error { return f(ctx, message) }
