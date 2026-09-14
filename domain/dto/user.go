// Package dto provides Data Transfer Objects (Params) for authentication operations.
package dto

import (
	"time"
)

type (
	// SignUpParams defines the data payload for user registration.
	SignUpParams struct {
		Name            string         `json:"name" binding:"required"`
		Email           string         `json:"email" binding:"required,email"`
		Password        string         `json:"password" binding:"required,min=6"`
		Username        string         `json:"username,omitzero"`
		DisplayUsername string         `json:"displayUsername,omitzero"`
		PhoneNumber     *string        `json:"phoneNumber,omitzero"`
		Role            string         `json:"role,omitzero"`
		Extra           map[string]any `json:"extra,omitzero"`
	}

	// SignInParams defines the credentials payload for authentication.
	SignInParams struct {
		Email    string         `json:"email" binding:"required,email"`
		Password string         `json:"password" binding:"required,min=6"`
		Extra    map[string]any `json:"extra,omitzero"`
	}

	// UpdateUserParams defines the data payload for updating user details.
	UpdateUserParams struct {
		ID                  string         `json:"id" binding:"required"`
		Name                string         `json:"name,omitzero"`
		Email               string         `json:"email,omitzero"`
		EmailVerified       *bool          `json:"emailVerified,omitzero"`
		Username            *string        `json:"username,omitzero"`
		DisplayUsername     *string        `json:"displayUsername,omitzero"`
		PhoneNumber         *string        `json:"phoneNumber,omitzero"`
		PhoneNumberVerified *bool          `json:"phoneNumberVerified,omitzero"`
		TwoFactorEnabled    *bool          `json:"twoFactorEnabled,omitzero"`
		Role                string         `json:"role,omitzero"`
		Banned              *bool          `json:"banned,omitzero"`
		BanReason           *string        `json:"banReason,omitzero"`
		BanExpires          *time.Time     `json:"banExpires,omitzero"`
		LastLoginMethod     *string        `json:"lastLoginMethod,omitzero"`
		Extra               map[string]any `json:"extra,omitzero"`
	}

	// ChangePasswordParams defines the payload for password change requests.
	ChangePasswordParams struct {
		UserID          string         `json:"userId"`
		CurrentPassword string         `json:"currentPassword" binding:"required"`
		NewPassword     string         `json:"newPassword" binding:"required,min=6"`
		Extra           map[string]any `json:"extra,omitzero"`
	}

	// SendVerificationEmailParams defines the payload for requesting an email verification link or token.
	SendVerificationEmailParams struct {
		Email       string         `json:"email" binding:"required,email"`
		CallbackURL string         `json:"callbackURL,omitzero"`
		Extra       map[string]any `json:"extra,omitzero"`
	}

	// VerifyEmailParams defines the token payload for email verification.
	VerifyEmailParams struct {
		Token string         `json:"token" binding:"required"`
		Extra map[string]any `json:"extra,omitzero"`
	}

	// VerifyPasswordParams defines the payload for checking if the provided password matches the user's current password.
	VerifyPasswordParams struct {
		UserID   string         `json:"userId" binding:"required"`
		Password string         `json:"password" binding:"required"`
		Extra    map[string]any `json:"extra,omitzero"`
	}

	// ForgotPasswordParams defines the payload for requesting a password reset email.
	ForgotPasswordParams struct {
		Email      string         `json:"email" binding:"required,email"`
		RedirectTo string         `json:"redirectTo,omitzero"`
		Extra      map[string]any `json:"extra,omitzero"`
	}

	// ResetPasswordParams defines the payload for setting a new password using a reset token.
	ResetPasswordParams struct {
		Token       string         `json:"token" binding:"required"`
		NewPassword string         `json:"newPassword" binding:"required,min=6"`
		Extra       map[string]any `json:"extra,omitzero"`
	}

	// CreateUserParams defines the mutable parameter payload passed to repository user creation operations.
	CreateUserParams struct {
		Email               string         `json:"email"`
		PasswordHash        string         `json:"-"`
		Name                string         `json:"name,omitzero"`
		Username            string         `json:"username,omitzero"`
		DisplayUsername     string         `json:"displayUsername,omitzero"`
		PhoneNumber         *string        `json:"phoneNumber,omitzero"`
		PhoneNumberVerified bool           `json:"phoneNumberVerified,omitzero"`
		TwoFactorEnabled    bool           `json:"twoFactorEnabled,omitzero"`
		Role                string         `json:"role,omitzero"`
		LastLoginMethod     *string        `json:"lastLoginMethod,omitzero"`
		IsAnonymous         bool           `json:"isAnonymous,omitzero"`
		Extra               map[string]any `json:"extra,omitzero"`
	}
)
