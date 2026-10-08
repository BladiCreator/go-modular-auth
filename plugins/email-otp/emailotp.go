package emailotp

import (
	"context"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth/verification"
)

// Purpose is the verification token purpose namespacing email OTP tokens.
const Purpose verification.Purpose = "email_otp:authenticate"

// AccountProvider identifies accounts provisioned through this plugin.
const AccountProvider = "email_otp"

// RequestInput contains parameters for requesting an OTP code.
type RequestInput struct {
	// Email is the destination email address. Required.
	Email string

	// Metadata carries optional application context.
	Metadata map[string]string
}

// VerifyInput contains parameters for verifying an OTP code.
type VerifyInput struct {
	// Email is the email address that requested the code. Required.
	Email string

	// Code is the numeric OTP code received by the user. Required.
	Code string

	// Session holds optional metadata (IP address, User Agent) recorded with the session.
	Session auth.SessionOptions
}

// EmailOTP is the strongly typed public capability exposed by this plugin.
// Applications consume it via auth.Get[plugins.EmailOTP]() or auth.Get[emailotp.EmailOTP]().
type EmailOTP interface {
	// Request generates and dispatches an OTP code to the requested email.
	// To prevent user enumeration, if AllowSignUp is false and the email is unknown,
	// this operation returns nil without sending an email.
	Request(ctx context.Context, in RequestInput) error

	// Verify validates and atomically consumes the single-use OTP code.
	// On success, it establishes an authenticated session and returns the AuthResult.
	// On failure (incorrect code, expired, replay, max attempts exceeded), it emits
	// an OTPRejected event and returns a domain error.
	Verify(ctx context.Context, in VerifyInput) (*auth.AuthResult, error)

	// Revoke invalidates any outstanding OTP codes issued for the email address.
	Revoke(ctx context.Context, email string) error
}

// Capability is an alias for EmailOTP for idiomatic capability retrieval.
type Capability = EmailOTP
