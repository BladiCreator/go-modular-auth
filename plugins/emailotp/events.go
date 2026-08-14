package emailotp

import (
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

// Event bus topic string constants emitted during Email OTP lifecycle operations.
const (
	// EventEmailOTPSendBefore is emitted right before dispatching an OTP to the recipient email.
	// Payload: *SendOTPPendingPayload
	EventEmailOTPSendBefore = "emailotp:send:before"

	// EventEmailOTPSent is emitted immediately after an OTP has been successfully dispatched.
	// Payload: *OTPSentPayload
	EventEmailOTPSent = "emailotp:send:after"

	// EventEmailOTPVerifyBefore is emitted right before verifying a submitted OTP code.
	// Payload: *VerifyBeforePayload
	EventEmailOTPVerifyBefore = "emailotp:verify:before"

	// EventEmailOTPVerified is emitted after an OTP code has been successfully verified.
	// Payload: *OTPVerifiedPayload
	EventEmailOTPVerified = "emailotp:verify:after"

	// EventEmailOTPSignInSuccess is emitted when a user successfully authenticates or registers via OTP.
	// Payload: *SignInSuccessPayload
	EventEmailOTPSignInSuccess = "emailotp:sign_in:success"

	// EventEmailOTPPasswordReset is emitted when a user resets their password using an OTP.
	// Payload: *PasswordResetPayload
	EventEmailOTPPasswordReset = "emailotp:password_reset:success"

	// EventEmailOTPChangeEmail is emitted when a user successfully updates their verified email address via OTP.
	// Payload: *EmailChangedPayload
	EventEmailOTPChangeEmail = "emailotp:change_email:success"

	// EventEmailOTPFailed is emitted when an incorrect OTP is submitted or verification fails.
	// Payload: *OTPFailedPayload
	EventEmailOTPFailed = "emailotp:verify:failed"

	// EventEmailOTPAttemptsExceeded is emitted when all allowed attempts on an OTP have been exhausted.
	// Payload: *OTPFailedPayload
	EventEmailOTPAttemptsExceeded = "emailotp:attempts:exceeded"

	// EventEmailOTPExpired is emitted when verification is attempted on an expired OTP.
	// Payload: *OTPFailedPayload
	EventEmailOTPExpired = "emailotp:expired"
)

// Typed Event Payloads
type (
	// SendOTPPendingPayload contains recipient and expiration details before dispatching an OTP.
	SendOTPPendingPayload struct {
		Email     string         `json:"email"`
		Type      OTPType        `json:"type"`
		ExpiresAt time.Time      `json:"expires_at"`
		Extra     map[string]any `json:"extra,omitempty"`
	}

	// OTPSentPayload contains confirmation details after an OTP has been dispatched.
	OTPSentPayload struct {
		Email     string         `json:"email"`
		Type      OTPType        `json:"type"`
		ExpiresAt time.Time      `json:"expires_at"`
		Extra     map[string]any `json:"extra,omitempty"`
	}

	// VerifyBeforePayload contains parameters before executing OTP verification.
	VerifyBeforePayload struct {
		Email string         `json:"email"`
		Type  OTPType        `json:"type"`
		Extra map[string]any `json:"extra,omitempty"`
	}

	// OTPVerifiedPayload reports details of a successful OTP code verification.
	OTPVerifiedPayload struct {
		UserID    string         `json:"user_id"`
		Email     string         `json:"email"`
		Type      OTPType        `json:"type"`
		Timestamp time.Time      `json:"timestamp"`
		Extra     map[string]any `json:"extra,omitempty"`
	}

	// SignInSuccessPayload reports authentication or auto-registration details upon OTP sign-in.
	SignInSuccessPayload struct {
		User      *entity.User    `json:"user"`
		Session   *entity.Session `json:"session"`
		IsNewUser bool            `json:"is_new_user"`
		Extra     map[string]any  `json:"extra,omitempty"`
	}

	// PasswordResetPayload reports details when a password is reset via OTP.
	PasswordResetPayload struct {
		UserID    string         `json:"user_id"`
		Email     string         `json:"email"`
		Timestamp time.Time      `json:"timestamp"`
		Extra     map[string]any `json:"extra,omitempty"`
	}

	// EmailChangedPayload reports details when an email address is changed and confirmed via OTP.
	EmailChangedPayload struct {
		UserID    string         `json:"user_id"`
		OldEmail  string         `json:"old_email"`
		NewEmail  string         `json:"new_email"`
		Timestamp time.Time      `json:"timestamp"`
		Extra     map[string]any `json:"extra,omitempty"`
	}

	// OTPFailedPayload reports diagnostic information for failed or expired OTP verification attempts.
	OTPFailedPayload struct {
		Email             string         `json:"email"`
		Type              OTPType        `json:"type"`
		AttemptsUsed      int            `json:"attempts_used"`
		AttemptsRemaining int            `json:"attempts_remaining"`
		Reason            string         `json:"reason"`
		Extra             map[string]any `json:"extra,omitempty"`
	}
)
