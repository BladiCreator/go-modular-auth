package phone

import (
	"context"

	"github.com/BladiCreator/go-modular-auth-phone/store"
	auth "github.com/BladiCreator/go-modular-auth"
)

const (
	// AccountProvider identifies Core accounts provisioned through this plugin.
	AccountProvider = "phone"

	// PurposeAuthenticate namespaces verification tokens used for OTP authentication.
	PurposeAuthenticate = "phone:authenticate"

	// PurposeVerify namespaces verification tokens used for initial phone ownership confirmation.
	PurposeVerify = "phone:verify"

	// PurposeChange namespaces verification tokens used for changing phone numbers.
	PurposeChange = "phone:change"
)

// Record is an alias to store.PhoneRecord in the public API.
type Record = store.PhoneRecord

// RequestOTPInput contains parameters for requesting an authentication OTP code.
type RequestOTPInput struct {
	// PhoneNumber is the destination mobile number (E.164 or unformatted). Required.
	PhoneNumber string

	// Metadata carries optional application context or vendor tags.
	Metadata map[string]string
}

// VerifyOTPInput contains parameters for verifying an OTP code and establishing a session.
type VerifyOTPInput struct {
	// PhoneNumber is the phone number that requested the code. Required.
	PhoneNumber string

	// Code is the numeric OTP received by the user. Required.
	Code string

	// Email is an optional email address used when registering a new user upon first sign-in.
	Email string

	// Session holds optional IP address and User Agent metadata for the session.
	Session auth.SessionOptions
}

// RequestVerificationInput contains parameters for requesting ownership verification for an existing user.
type RequestVerificationInput struct {
	// UserID identifies the user to whom the phone is being linked. Required.
	UserID string

	// PhoneNumber is the phone number to verify. Required.
	PhoneNumber string

	// Metadata carries optional context.
	Metadata map[string]string
}

// ConfirmVerificationInput contains parameters for confirming ownership of a phone number.
type ConfirmVerificationInput struct {
	// UserID identifies the user. Required.
	UserID string

	// PhoneNumber is the phone number to confirm. Required.
	PhoneNumber string

	// Code is the numeric OTP code received on the device. Required.
	Code string
}

// RequestChangeInput contains parameters for initiating a phone number change for an existing user.
type RequestChangeInput struct {
	// UserID identifies the user changing their phone number. Required.
	UserID string

	// NewPhoneNumber is the replacement phone number. Required.
	NewPhoneNumber string

	// Metadata carries optional context.
	Metadata map[string]string
}

// ConfirmChangeInput contains parameters for confirming a phone number change.
type ConfirmChangeInput struct {
	// UserID identifies the user. Required.
	UserID string

	// NewPhoneNumber is the new phone number to confirm. Required.
	NewPhoneNumber string

	// Code is the numeric verification code sent to the new phone number. Required.
	Code string
}

// RemoveInput contains parameters for unlinking and deleting a user's phone number.
type RemoveInput struct {
	// UserID identifies the user whose phone record is being deleted. Required.
	UserID string
}

// Phone is the strongly typed public capability exposed by this plugin.
// Applications consume it via auth.Get[plugins.Phone]() or auth.Get[phone.Phone]().
type Phone interface {
	// RequestOTP dispatches an authentication OTP code to the provided phone number.
	// If AllowSignUp is false and the phone number is unregistered, this method returns nil
	// without dispatching an SMS, protecting against user enumeration.
	RequestOTP(ctx context.Context, in RequestOTPInput) error

	// VerifyOTP validates and atomically consumes the single-use OTP code.
	// On success, it provisions or retrieves the user, links the phone account, and returns an AuthResult.
	// On failure (incorrect code, expired, replay, max attempts exceeded), it emits a rejection event
	// and returns a domain error.
	VerifyOTP(ctx context.Context, in VerifyOTPInput) (*auth.AuthResult, error)

	// RequestVerification dispatches an OTP to verify a user's ownership of a phone number.
	RequestVerification(ctx context.Context, in RequestVerificationInput) error

	// ConfirmVerification validates the OTP and marks the user's phone record as verified.
	ConfirmVerification(ctx context.Context, in ConfirmVerificationInput) (*Record, error)

	// RequestChange dispatches an OTP to a new phone number to begin changing the user's phone number.
	RequestChange(ctx context.Context, in RequestChangeInput) error

	// ConfirmChange validates the OTP sent to the new phone and atomically updates the user's phone number.
	ConfirmChange(ctx context.Context, in ConfirmChangeInput) (*Record, error)

	// Remove unlinks and removes the phone record for the specified user.
	Remove(ctx context.Context, in RemoveInput) error

	// GetByUserID retrieves the phone record associated with a Core user ID.
	GetByUserID(ctx context.Context, userID string) (*Record, error)

	// GetByPhone retrieves the phone record associated with a normalized phone number.
	GetByPhone(ctx context.Context, phoneNumber string) (*Record, error)

	// Normalize transforms and validates a raw phone string into canonical E.164 format.
	Normalize(raw string) (string, error)

	// Validate checks whether a normalized phone number complies with ITU-T E.164 format.
	Validate(normalized string) error
}

// Capability is an alias for Phone for idiomatic capability retrieval.
type Capability = Phone
