package entity

import "time"

// VerificationToken represents a token used for email verification or password reset operations.
type VerificationToken struct {
	Identifier string    `json:"identifier"`
	Token      string    `json:"token"`
	ExpiresAt  time.Time `json:"expiresAt"`
}
