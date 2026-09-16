package entity

import "time"

// Verification represents a standard ephemeral verification record (token, OTP, or secret)
// used across authentication plugins (e.g. emailpassword, magiclink, emailotp, phonenumber, ott).
type Verification struct {
	// ID is the unique record identifier (typically a UUIDv7).
	ID string `json:"id"`

	// Identifier is the composite lookup key (e.g. email address, phone number, or raw token string).
	Identifier string `json:"identifier"`

	// Value stores the secret token, hashed OTP, or associated session/user payload.
	Value string `json:"value"`

	// ExpiresAt specifies the exact timestamp when this verification record becomes invalid.
	ExpiresAt time.Time `json:"expiresAt"`

	// CreatedAt records when the verification record was initialized.
	CreatedAt time.Time `json:"createdAt"`

	// UpdatedAt records when the verification record was last modified, if applicable.
	UpdatedAt *time.Time `json:"updatedAt,omitzero"`
}
