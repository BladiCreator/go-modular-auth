package passkey

import (
	"context"

	auth "github.com/BladiCreator/go-modular-auth"
)

// Hooks provides lifecycle intervention points for passkey operations.
type Hooks struct {
	BeforeBeginRegistration  func(ctx context.Context, in *BeginRegistrationInput) error
	BeforeFinishRegistration func(ctx context.Context, in *FinishRegistrationInput) error
	AfterRegistration        func(ctx context.Context, cred *Passkey) error

	BeforeBeginAuthentication  func(ctx context.Context, in *BeginAuthenticationInput) error
	BeforeFinishAuthentication func(ctx context.Context, in *FinishAuthenticationInput) error
	AfterAuthentication        func(ctx context.Context, res *auth.AuthResult) error
}

// NewHooks creates an initialized Hooks structure.
func NewHooks() *Hooks {
	return &Hooks{}
}

func (h *Hooks) runBeforeBeginRegistration(ctx context.Context, in *BeginRegistrationInput) error {
	if h != nil && h.BeforeBeginRegistration != nil {
		return h.BeforeBeginRegistration(ctx, in)
	}
	return nil
}

func (h *Hooks) runBeforeFinishRegistration(ctx context.Context, in *FinishRegistrationInput) error {
	if h != nil && h.BeforeFinishRegistration != nil {
		return h.BeforeFinishRegistration(ctx, in)
	}
	return nil
}

func (h *Hooks) runAfterRegistration(ctx context.Context, cred *Passkey) error {
	if h != nil && h.AfterRegistration != nil {
		return h.AfterRegistration(ctx, cred)
	}
	return nil
}

func (h *Hooks) runBeforeBeginAuthentication(ctx context.Context, in *BeginAuthenticationInput) error {
	if h != nil && h.BeforeBeginAuthentication != nil {
		return h.BeforeBeginAuthentication(ctx, in)
	}
	return nil
}

func (h *Hooks) runBeforeFinishAuthentication(ctx context.Context, in *FinishAuthenticationInput) error {
	if h != nil && h.BeforeFinishAuthentication != nil {
		return h.BeforeFinishAuthentication(ctx, in)
	}
	return nil
}

func (h *Hooks) runAfterAuthentication(ctx context.Context, res *auth.AuthResult) error {
	if h != nil && h.AfterAuthentication != nil {
		return h.AfterAuthentication(ctx, res)
	}
	return nil
}
