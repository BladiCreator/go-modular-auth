package username_test

import (
	"errors"
	"testing"

	"github.com/BladiCreator/go-modular-auth-username"
)

func TestDefaultNormalizer(t *testing.T) {
	norm := username.DefaultNormalizer(false)

	// Trims whitespace and lowercases
	got, err := norm("  AliceSmith  ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "alicesmith" {
		t.Fatalf("expected alicesmith, got %s", got)
	}

	// Empty string
	if _, err := norm("   "); !errors.Is(err, username.ErrInvalidFormat) {
		t.Fatalf("expected ErrInvalidFormat for whitespace-only, got %v", err)
	}

	// Case sensitive normalizer keeps original casing
	normCase := username.DefaultNormalizer(true)
	gotCase, err := normCase("  AliceSmith  ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotCase != "AliceSmith" {
		t.Fatalf("expected AliceSmith, got %s", gotCase)
	}
}

func TestDefaultValidator(t *testing.T) {
	validator := username.DefaultValidator(3, 20, username.DefaultReservedUsernames)

	tests := []struct {
		input   string
		wantErr error
	}{
		{"alice", nil},
		{"alice_123", nil},
		{"john-doe", nil},
		{"a_b", nil},
		{"al", username.ErrTooShort},
		{"very_long_username_exceeding_limit", username.ErrTooLong},
		{"-alice", username.ErrInvalidFormat}, // leading hyphen
		{"alice-", username.ErrInvalidFormat}, // trailing hyphen
		{"_alice", username.ErrInvalidFormat}, // leading underscore
		{"alice_", username.ErrInvalidFormat}, // trailing underscore
		{"alice--doe", username.ErrInvalidFormat}, // consecutive hyphens
		{"alice__doe", username.ErrInvalidFormat}, // consecutive underscores
		{"alice@doe", username.ErrInvalidFormat},  // invalid character
		{"admin", username.ErrReserved},       // reserved name
		{"ADMIN", username.ErrReserved},       // reserved name case-insensitive
		{"root", username.ErrReserved},
		{"api", username.ErrReserved},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			err := validator(tc.input)
			if tc.wantErr == nil && err != nil {
				t.Fatalf("expected nil error for %q, got: %v", tc.input, err)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("expected %v for %q, got: %v", tc.wantErr, tc.input, err)
			}
		})
	}
}
