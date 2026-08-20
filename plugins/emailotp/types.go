package emailotp

import (
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/plugin"
)

// Parameter and Result Structs
type (
	// SendVerificationOTPParams defines parameters required to dispatch an OTP to a user's email.
	SendVerificationOTPParams struct {
		// Email is the destination recipient email address (required).
		Email string `json:"email"`

		// Type specifies the OTP workflow type ("email-verification", "sign-in", "forget-password", "change-email").
		Type OTPType `json:"type"`

		plugin.ExtraContainer
	}

	// SendVerificationOTPResult contains the delivery status and expiry of the dispatched OTP.
	SendVerificationOTPResult struct {
		// Success indicates if the OTP was successfully generated and dispatched.
		Success bool `json:"success"`

		// ExpiresAt indicates when the dispatched OTP code will expire.
		ExpiresAt time.Time `json:"expires_at"`
	}

	// CreateVerificationOTPParams defines parameters for server-side OTP generation without email dispatch.
	CreateVerificationOTPParams struct {
		// Email is the target email address.
		Email string `json:"email"`

		// Type specifies the OTP workflow type.
		Type OTPType `json:"type"`

		plugin.ExtraContainer
	}

	// GetVerificationOTPParams defines parameters for server-side inspection of an active OTP code.
	GetVerificationOTPParams struct {
		// Email is the target email address.
		Email string `json:"email"`

		// Type specifies the OTP workflow type.
		Type OTPType `json:"type"`

		plugin.ExtraContainer
	}

	// GetVerificationOTPResult contains the plain text OTP code retrieved from storage.
	GetVerificationOTPResult struct {
		// OTP is the retrieved plain text code.
		OTP string `json:"otp"`
	}

	// CheckVerificationOTPParams defines parameters for validating an OTP without consuming it.
	CheckVerificationOTPParams struct {
		// Email is the target email address.
		Email string `json:"email"`

		// Type specifies the OTP workflow type.
		Type OTPType `json:"type"`

		// OTP is the code to check.
		OTP string `json:"otp"`

		plugin.ExtraContainer
	}

	// CheckVerificationOTPResult reports whether the tested OTP code is valid.
	CheckVerificationOTPResult struct {
		// Success indicates whether the OTP is currently valid.
		Success bool `json:"success"`
	}

	// VerifyEmailOTPParams defines parameters to verify email ownership via OTP.
	VerifyEmailOTPParams struct {
		// Email is the address being verified.
		Email string `json:"email"`

		// OTP is the verification code submitted by the user.
		OTP string `json:"otp"`

		plugin.ExtraContainer
	}

	// VerifyEmailOTPResult contains the updated user profile and optional auto-created session.
	VerifyEmailOTPResult struct {
		// Success indicates successful email verification.
		Success bool `json:"success"`

		// User is the updated user entity with EmailVerified set to true.
		User *entity.User `json:"user"`

		// SessionToken is the raw token string if AutoSignInAfterVerification is enabled.
		SessionToken string `json:"session_token,omitempty"`

		// Session is the active session entity if AutoSignInAfterVerification is enabled.
		Session *entity.Session `json:"session,omitempty"`
	}

	// SignInEmailOTPParams defines parameters for passwordless sign-in and auto-registration via OTP.
	SignInEmailOTPParams struct {
		// Email is the user's email address.
		Email string `json:"email"`

		// OTP is the one-time code submitted by the user.
		OTP string `json:"otp"`

		// Name is the optional display name assigned if a new user is created.
		Name string `json:"name,omitempty"`

		plugin.ExtraContainer
	}

	// SignInEmailOTPResult contains the authenticated user profile, session, and registration indicator.
	SignInEmailOTPResult struct {
		// User is the authenticated or newly provisioned user entity.
		User *entity.User `json:"user"`

		// SessionToken is the raw session token.
		SessionToken string `json:"session_token"`

		// Session is the persisted active session entity.
		Session *entity.Session `json:"session"`

		// IsNewUser indicates if this sign-in operation provisioned a new user account.
		IsNewUser bool `json:"is_new_user"`
	}

	// RequestPasswordResetParams defines parameters to request a password reset OTP.
	RequestPasswordResetParams struct {
		// Email is the account email requesting a password reset.
		Email string `json:"email"`

		plugin.ExtraContainer
	}

	// RequestPasswordResetResult reports the result of the password reset dispatch request.
	RequestPasswordResetResult struct {
		// Success indicates if the reset OTP was successfully dispatched.
		Success bool `json:"success"`
	}

	// ResetPasswordParams defines parameters for setting a new password using a verified OTP.
	ResetPasswordParams struct {
		// Email is the account email address.
		Email string `json:"email"`

		// OTP is the reset code submitted by the user.
		OTP string `json:"otp"`

		// NewPassword is the new password string to set.
		NewPassword string `json:"new_password"`

		plugin.ExtraContainer
	}

	// ResetPasswordResult reports whether the password was successfully updated.
	ResetPasswordResult struct {
		// Success indicates if the password was successfully reset.
		Success bool `json:"success"`
	}

	// RequestEmailChangeParams defines parameters to initiate an email change flow.
	RequestEmailChangeParams struct {
		// UserID is the ID of the authenticated user requesting the change.
		UserID string `json:"user_id"`

		// NewEmail is the new email address to bind to the account.
		NewEmail string `json:"new_email"`

		// OTP is the verification code for the current email if VerifyCurrentEmail is enabled.
		OTP string `json:"otp,omitempty"`

		plugin.ExtraContainer
	}

	// RequestEmailChangeResult reports whether the email change OTP was dispatched to the new email.
	RequestEmailChangeResult struct {
		// Success indicates if the OTP was successfully dispatched to the new email address.
		Success bool `json:"success"`
	}

	// ChangeEmailParams defines parameters to confirm an email change using the OTP sent to the new email.
	ChangeEmailParams struct {
		// UserID is the ID of the authenticated user.
		UserID string `json:"user_id"`

		// NewEmail is the new verified email address.
		NewEmail string `json:"new_email"`

		// OTP is the confirmation code delivered to the new email.
		OTP string `json:"otp"`

		plugin.ExtraContainer
	}

	// ChangeEmailResult reports the outcome of the email change confirmation.
	ChangeEmailResult struct {
		// Success indicates if the email was successfully changed.
		Success bool `json:"success"`

		// User is the updated user entity with the new email address.
		User *entity.User `json:"user"`
	}
)
