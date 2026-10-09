package smtp_test

import (
	"context"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth/adapters/smtp"
	"github.com/BladiCreator/go-modular-auth/email"
)

func TestInterfaceCompliance(t *testing.T) {
	var _ email.Sender = (*smtp.Sender)(nil)
}

func TestConfigValidation(t *testing.T) {
	_, err := smtp.New(smtp.Config{})
	if err == nil {
		t.Fatal("expected error on empty host")
	}

	_, err = smtp.New(smtp.Config{Host: "smtp.example.com"})
	if err == nil {
		t.Fatal("expected error on empty from address")
	}

	s, err := smtp.New(smtp.Config{
		Host: "smtp.example.com",
		From: "no-reply@example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s == nil {
		t.Fatal("expected non-nil sender")
	}
}

func TestContextCancellation(t *testing.T) {
	s, err := smtp.New(smtp.Config{
		Host: "127.0.0.1",
		Port: 65534, // unreachable port
		From: "no-reply@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	err = s.Send(ctx, email.Message{
		To:      "user@example.com",
		Subject: "Test",
		Text:    "Hello",
	})
	if err == nil {
		t.Fatal("expected error on canceled context")
	}
}
