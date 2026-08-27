// Package dto provides Data Transfer Objects (Params) for authentication operations.
package dto

import (
	"github.com/BladiCreator/go-modular-auth/plugin"
)

type (
	// SignUpParams defines the data payload for user registration.
	SignUpParams struct {
		Name     string `json:"name" binding:"required"`
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=6"`
		plugin.ExtraContainer
	}

	// SignInParams defines the credentials payload for authentication.
	SignInParams struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=6"`
		plugin.ExtraContainer
	}

	// UpdateUserParams defines the data payload for updating user details.
	UpdateUserParams struct {
		Name  string `json:"name" binding:"required"`
		Email string `json:"email" binding:"required,email"`
		plugin.ExtraContainer
	}

	// ChangePasswordParams defines the payload for password change requests.
	ChangePasswordParams struct {
		UserID          string `json:"userId"`
		CurrentPassword string `json:"currentPassword" binding:"required"`
		NewPassword     string `json:"newPassword" binding:"required,min=6"`
		plugin.ExtraContainer
	}

	// SendVerificationEmailParams defines the payload for requesting an email verification link or token.
	SendVerificationEmailParams struct {
		Email string `json:"email" binding:"required,email"`
		plugin.ExtraContainer
	}

	// VerifyEmailParams defines the token payload for email verification.
	VerifyEmailParams struct {
		Token string `json:"token" binding:"required"`
		plugin.ExtraContainer
	}

	// VerifyPasswordParams defines the payload for checking if the provided password matches the user's current password.
	VerifyPasswordParams struct {
		UserID   string `json:"userId" binding:"required"`
		Password string `json:"password" binding:"required"`
		plugin.ExtraContainer
	}

	// ForgotPasswordParams defines the payload for requesting a password reset email.
	ForgotPasswordParams struct {
		Email string `json:"email" binding:"required,email"`
		plugin.ExtraContainer
	}

	// ResetPasswordParams defines the payload for setting a new password using a reset token.
	ResetPasswordParams struct {
		Token       string `json:"token" binding:"required"`
		NewPassword string `json:"newPassword" binding:"required,min=6"`
		plugin.ExtraContainer
	}

	// CreateUserParams defines the mutable parameter payload passed to repository user creation operations.
	CreateUserParams struct {
		Email           string  `json:"email"`
		PasswordHash    string  `json:"-"`
		Name            string  `json:"name"`
		Role            string  `json:"role,omitempty"`
		LastLoginMethod *string `json:"lastLoginMethod,omitempty"`
		plugin.ExtraContainer
	}
)
