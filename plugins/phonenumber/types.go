package phonenumber

import (
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/plugin"
)

// Parameter and Result Structs
type (
	// SendOTPParams defines parameters required to dispatch an OTP to a user's phone number.
	SendOTPParams struct {
		// PhoneNumber is the destination recipient phone number (required).
		PhoneNumber string `json:"phone_number"`

		plugin.ExtraContainer
	}

	// SendOTPResult contains the delivery status and expiry of the dispatched OTP.
	SendOTPResult struct {
		// Success indicates if the OTP was successfully generated and dispatched.
		Success bool `json:"success"`

		// ExpiresAt indicates when the dispatched OTP code will expire.
		ExpiresAt time.Time `json:"expires_at"`
	}

	// VerifyParams defines parameters to verify a phone number OTP for login, registration, or profile update.
	VerifyParams struct {
		// PhoneNumber is the phone number being verified (required).
		PhoneNumber string `json:"phone_number"`

		// Code is the verification code submitted by the user (required).
		Code string `json:"code"`

		// UserID is the ID of the authenticated user (required if UpdatePhoneNumber is true).
		UserID string `json:"user_id,omitempty"`

		// UpdatePhoneNumber indicates whether to attach the verified phone number to an existing user session.
		UpdatePhoneNumber bool `json:"update_phone_number,omitempty"`

		// DisableSession prevents creating an active authentication session upon successful verification.
		DisableSession bool `json:"disable_session,omitempty"`

		plugin.ExtraContainer
	}

	// VerifyResult contains the updated user profile and optional created session.
	VerifyResult struct {
		// Success indicates successful phone verification.
		Success bool `json:"success"`

		// User is the authenticated, newly provisioned, or updated user entity.
		User *entity.User `json:"user"`

		// SessionToken is the raw session token if a session was created.
		SessionToken string `json:"session_token,omitempty"`

		// Session is the active session entity if created.
		Session *entity.Session `json:"session,omitempty"`
	}

	// SignInParams defines parameters for credential-based phone number + password login.
	SignInParams struct {
		// PhoneNumber is the registered user's phone number.
		PhoneNumber string `json:"phone_number"`

		// Password is the plain text password.
		Password string `json:"password"`

		// RememberMe extends session lifespan if set to true.
		RememberMe *bool `json:"remember_me,omitempty"`

		plugin.ExtraContainer
	}

	// SignInResult contains the authenticated user and active session.
	SignInResult struct {
		// User is the authenticated user entity.
		User *entity.User `json:"user"`

		// SessionToken is the raw session token.
		SessionToken string `json:"session_token"`

		// Session is the persisted active session entity.
		Session *entity.Session `json:"session"`
	}

	// RequestPasswordResetParams defines parameters to request a password reset OTP via SMS.
	RequestPasswordResetParams struct {
		// PhoneNumber is the account phone number requesting a password reset.
		PhoneNumber string `json:"phone_number"`

		plugin.ExtraContainer
	}

	// RequestPasswordResetResult reports the result of the password reset dispatch request.
	RequestPasswordResetResult struct {
		// Success indicates if the reset OTP was successfully dispatched.
		Success bool `json:"success"`
	}

	// ResetPasswordParams defines parameters for setting a new password using a verified SMS OTP.
	ResetPasswordParams struct {
		// PhoneNumber is the account phone number.
		PhoneNumber string `json:"phone_number"`

		// OTP is the reset code submitted by the user.
		OTP string `json:"otp"`

		// NewPassword is the new password string to set.
		NewPassword string `json:"new_password"`

		plugin.ExtraContainer
	}

	// ResetPasswordResult reports whether the password was successfully reset.
	ResetPasswordResult struct {
		// Success indicates if the password was successfully reset.
		Success bool `json:"success"`
	}

	// CreateVerificationOTPParams defines parameters for server-side OTP generation without SMS dispatch.
	CreateVerificationOTPParams struct {
		// PhoneNumber is the target phone number.
		PhoneNumber string `json:"phone_number"`

		// Type specifies the OTP workflow type.
		Type OTPType `json:"type"`

		plugin.ExtraContainer
	}

	// CreateVerificationOTPResult contains the status and expiry of the created OTP.
	CreateVerificationOTPResult struct {
		// Success indicates if the OTP record was created.
		Success bool `json:"success"`

		// ExpiresAt indicates when the created OTP will expire.
		ExpiresAt time.Time `json:"expires_at"`
	}

	// GetVerificationOTPParams defines parameters for server-side inspection of an active OTP code.
	GetVerificationOTPParams struct {
		// PhoneNumber is the target phone number.
		PhoneNumber string `json:"phone_number"`

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
		// PhoneNumber is the target phone number.
		PhoneNumber string `json:"phone_number"`

		// Type specifies the OTP workflow type.
		Type OTPType `json:"type"`

		// OTP is the code to check.
		OTP string `json:"otp"`

		plugin.ExtraContainer
	}

	// CheckVerificationOTPResult reports whether the tested OTP code is currently valid.
	CheckVerificationOTPResult struct {
		// Success indicates whether the OTP is currently valid.
		Success bool `json:"success"`
	}
)
