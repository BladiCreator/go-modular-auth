package phonenumber

import (
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/plugin"
)

// Event bus topic string constants emitted during Phone Number lifecycle operations.
const (
	// EventPhoneNumberOTPSendBefore is emitted right before dispatching an OTP to the recipient phone number.
	// Payload: *OTPSentPayload
	EventPhoneNumberOTPSendBefore = "phonenumber:otp:send:before"

	// EventPhoneNumberOTPSent is emitted immediately after an OTP has been successfully dispatched.
	// Payload: *OTPSentPayload
	EventPhoneNumberOTPSent = "phonenumber:otp:send:after"

	// EventPhoneNumberOTPVerifyBefore is emitted right before verifying a submitted OTP code.
	// Payload: *OTPSentPayload
	EventPhoneNumberOTPVerifyBefore = "phonenumber:otp:verify:before"

	// EventPhoneNumberOTPVerified is emitted after an OTP code has been successfully verified.
	// Payload: *OTPVerifiedPayload
	EventPhoneNumberOTPVerified = "phonenumber:otp:verify:after"

	// EventPhoneNumberOTPFailed is emitted when an incorrect OTP is submitted.
	// Payload: *OTPFailedPayload
	EventPhoneNumberOTPFailed = "phonenumber:otp:verify:failed"

	// EventPhoneNumberOTPAttemptsExceeded is emitted when all allowed attempts on an OTP have been exhausted.
	// Payload: *OTPFailedPayload
	EventPhoneNumberOTPAttemptsExceeded = "phonenumber:otp:attempts:exceeded"

	// EventPhoneNumberOTPExpired is emitted when verification is attempted on an expired OTP.
	// Payload: *OTPFailedPayload
	EventPhoneNumberOTPExpired = "phonenumber:otp:expired"

	// EventPhoneNumberSignInSuccess is emitted when a user successfully authenticates via phone OTP.
	// Payload: *SignInSuccessPayload
	EventPhoneNumberSignInSuccess = "phonenumber:signin:success"

	// EventPhoneNumberSignUpSuccess is emitted when a new user is provisioned upon phone OTP verification.
	// Payload: *SignInSuccessPayload
	EventPhoneNumberSignUpSuccess = "phonenumber:signup:success"

	// EventPhoneNumberSignInPasswordSuccess is emitted when a user authenticates using phone + password.
	// Payload: *SignInSuccessPayload
	EventPhoneNumberSignInPasswordSuccess = "phonenumber:signin_password:success"

	// EventPhoneNumberUpdated is emitted when a user's phone number is updated after verification.
	// Payload: *entity.User
	EventPhoneNumberUpdated = "phonenumber:updated"

	// EventPhoneNumberUnlinked is emitted when a user's phone number is removed.
	// Payload: *entity.User
	EventPhoneNumberUnlinked = "phonenumber:unlinked"

	// EventPhoneNumberPasswordResetRequested is emitted when a password reset OTP is requested for a phone number.
	// Payload: *OTPSentPayload
	EventPhoneNumberPasswordResetRequested = "phonenumber:password_reset:requested"

	// EventPhoneNumberPasswordResetSuccess is emitted when a user resets their password using a phone OTP.
	// Payload: *PasswordResetPayload
	EventPhoneNumberPasswordResetSuccess = "phonenumber:password_reset:success"
)

// Typed Event Payloads
type (
	// OTPSentPayload contains recipient and expiration details for dispatched OTPs.
	OTPSentPayload struct {
		PhoneNumber string    `json:"phone_number"`
		Type        OTPType   `json:"type"`
		ExpiresAt   time.Time `json:"expires_at"`
		plugin.ExtraContainer
	}

	// OTPFailedPayload contains details when OTP verification fails or reaches limits.
	OTPFailedPayload struct {
		PhoneNumber       string  `json:"phone_number"`
		Type              OTPType `json:"type"`
		AttemptsUsed      int     `json:"attempts_used"`
		AttemptsRemaining int     `json:"attempts_remaining"`
		Reason            string  `json:"reason"`
		plugin.ExtraContainer
	}

	// OTPVerifiedPayload reports details of a successful OTP code verification.
	OTPVerifiedPayload struct {
		UserID      string    `json:"user_id"`
		PhoneNumber string    `json:"phone_number"`
		Type        OTPType   `json:"type"`
		Timestamp   time.Time `json:"timestamp"`
		plugin.ExtraContainer
	}

	// SignInSuccessPayload reports authentication or auto-registration details upon phone login.
	SignInSuccessPayload struct {
		User      *entity.User    `json:"user"`
		Session   *entity.Session `json:"session,omitempty"`
		IsNewUser bool            `json:"is_new_user"`
		plugin.ExtraContainer
	}

	// PasswordResetPayload reports details when a password is reset via SMS OTP.
	PasswordResetPayload struct {
		UserID      string    `json:"user_id"`
		PhoneNumber string    `json:"phone_number"`
		Timestamp   time.Time `json:"timestamp"`
		plugin.ExtraContainer
	}
)
