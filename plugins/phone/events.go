package phone

import "time"

const (
	// EventPhoneOTPRequested is published when an OTP is successfully generated and dispatched.
	EventPhoneOTPRequested = "phone.otp.requested"

	// EventPhoneOTPVerified is published when an OTP code is verified and authentication completes.
	EventPhoneOTPVerified = "phone.otp.verified"

	// EventPhoneOTPRejected is published when an OTP verification attempt fails.
	EventPhoneOTPRejected = "phone.otp.rejected"

	// EventPhoneVerified is published when a phone number is validated and confirmed for a user.
	EventPhoneVerified = "phone.verified"

	// EventPhoneChanged is published when a user replaces their phone number with a new verified one.
	EventPhoneChanged = "phone.changed"

	// EventPhoneRemoved is published when a user unlinks or removes their phone number.
	EventPhoneRemoved = "phone.removed"
)

// OTPRequestedPayload carries metadata about an OTP dispatch event.
// Sensitive data (raw code, salt, hash) is strictly excluded.
type OTPRequestedPayload struct {
	PhoneNumber string    `json:"phone_number"`
	Subject     string    `json:"subject"`
	Purpose     string    `json:"purpose"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// OTPVerifiedPayload carries metadata about an authenticated session established via phone OTP.
type OTPVerifiedPayload struct {
	UserID      string    `json:"user_id"`
	PhoneNumber string    `json:"phone_number"`
	SessionID   string    `json:"session_id,omitempty"`
	VerifiedAt  time.Time `json:"verified_at"`
}

// OTPRejectedPayload carries diagnostic information when an OTP verification fails.
type OTPRejectedPayload struct {
	PhoneNumber string    `json:"phone_number"`
	Reason      string    `json:"reason"`
	Attempts    int       `json:"attempts"`
	Time        time.Time `json:"time"`
}

// PhoneVerifiedPayload carries metadata when a user successfully verifies their phone number.
type PhoneVerifiedPayload struct {
	UserID      string    `json:"user_id"`
	PhoneNumber string    `json:"phone_number"`
	VerifiedAt  time.Time `json:"verified_at"`
}

// PhoneChangedPayload carries metadata when a user's phone number is updated.
type PhoneChangedPayload struct {
	UserID    string    `json:"user_id"`
	OldPhone  string    `json:"old_phone"`
	NewPhone  string    `json:"new_phone"`
	ChangedAt time.Time `json:"changed_at"`
}

// PhoneRemovedPayload carries metadata when a user's phone number is deleted.
type PhoneRemovedPayload struct {
	UserID      string    `json:"user_id"`
	PhoneNumber string    `json:"phone_number"`
	RemovedAt   time.Time `json:"removed_at"`
}
