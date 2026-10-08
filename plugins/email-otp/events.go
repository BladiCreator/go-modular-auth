package emailotp

import (
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
)

const (
	// EventOTPRequested is emitted when an OTP code has been generated and dispatched.
	EventOTPRequested auth.EventName = "email_otp.requested"

	// EventOTPVerified is emitted when an OTP code is successfully and atomically verified.
	EventOTPVerified auth.EventName = "email_otp.verified"

	// EventOTPRejected is emitted when an OTP verification attempt fails (wrong code, expired, max attempts).
	EventOTPRejected auth.EventName = "email_otp.rejected"
)

// OTPRequestedPayload conveys non-sensitive event metadata when an OTP is dispatched.
// Plaintext codes and hashes are strictly excluded.
type OTPRequestedPayload struct {
	Email     string    `json:"email"`
	Subject   string    `json:"subject"`
	ExpiresAt time.Time `json:"expires_at"`
}

// OTPVerifiedPayload conveys non-sensitive event metadata when an OTP is verified.
type OTPVerifiedPayload struct {
	UserID     string    `json:"user_id"`
	Email      string    `json:"email"`
	SessionID  string    `json:"session_id"`
	VerifiedAt time.Time `json:"verified_at"`
}

// OTPRejectedPayload conveys non-sensitive security telemetry when verification is rejected.
type OTPRejectedPayload struct {
	Email    string    `json:"email"`
	Reason   string    `json:"reason"`
	Attempts int       `json:"attempts"`
	Time     time.Time `json:"time"`
}
