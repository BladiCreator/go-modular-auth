// Package user defines the User entity: the identity that authenticates.
package user

import (
	"errors"
	"net/mail"
	"strings"
	"time"
)

// ErrInvalidEmail is returned when an email address cannot be parsed.
var ErrInvalidEmail = errors.New("user: invalid email address")

// User represents a user identity. Plugins extend the model with their own
// stores keyed by User.ID instead of adding fields to the core entity.
type User struct {
	ID            string    `json:"id"`
	Email         string    `json:"email"`
	EmailVerified bool      `json:"email_verified"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// NormalizeEmail trims and lowercases an email address and validates that it
// is a bare address (no display name). Normalization guarantees that lookups
// and uniqueness constraints behave consistently across store adapters.
func NormalizeEmail(email string) (string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return "", ErrInvalidEmail
	}
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email || addr.Name != "" {
		return "", ErrInvalidEmail
	}
	return email, nil
}
