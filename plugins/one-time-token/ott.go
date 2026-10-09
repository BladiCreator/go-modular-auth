package ott

import (
	"context"
	"time"

	"github.com/BladiCreator/go-modular-auth/verification"
)

// GenerateOptions contains per-token options.
type GenerateOptions struct {
	TTL     time.Duration
	Purpose verification.Purpose
}

// GenerateOption mutates GenerateOptions.
type GenerateOption func(*GenerateOptions)

// WithCustomTTL overrides the token TTL for a single generation.
func WithCustomTTL(ttl time.Duration) GenerateOption {
	return func(o *GenerateOptions) {
		o.TTL = ttl
	}
}

// WithCustomPurpose overrides the token purpose for a single generation.
func WithCustomPurpose(p verification.Purpose) GenerateOption {
	return func(o *GenerateOptions) {
		o.Purpose = p
	}
}

// OneTimeToken defines the public capability exposed by this plugin.
type OneTimeToken interface {
	// Generate creates a secure, single-use token bound to subject.
	Generate(ctx context.Context, subject string, opts ...GenerateOption) (string, error)

	// Consume atomically consumes the token and returns the underlying verification token.
	Consume(ctx context.Context, token string, opts ...GenerateOption) (*verification.Token, error)

	// Revoke invalidates all active tokens for the given subject.
	Revoke(ctx context.Context, subject string, opts ...GenerateOption) error
}
