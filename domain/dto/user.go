// Package dto provides Data Transfer Objects (Params) for authentication operations.
package dto

import (
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

type (
	// SignUpParams defines the data payload for user registration.
	SignUpParams struct {
		Name     string `json:"name" binding:"required"`
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=6"`
		entity.ExtraContainer
	}

	// SignInParams defines the credentials payload for authentication.
	SignInParams struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=6"`
		entity.ExtraContainer
	}

	// UpdateUserParams defines the data payload for updating user details.
	UpdateUserParams struct {
		ID                  string     `json:"id" binding:"required"`
		Name                string     `json:"name,omitempty"`
		Email               string     `json:"email,omitempty"`
		EmailVerified       *bool      `json:"emailVerified,omitempty"`
		PhoneNumber         *string    `json:"phoneNumber,omitempty"`
		PhoneNumberVerified *bool      `json:"phoneNumberVerified,omitempty"`
		TwoFactorEnabled    *bool      `json:"twoFactorEnabled,omitempty"`
		Role                string     `json:"role,omitempty"`
		Banned              *bool      `json:"banned,omitempty"`
		BanReason           *string    `json:"banReason,omitempty"`
		BanExpires          *time.Time `json:"banExpires,omitempty"`
		LastLoginMethod     *string    `json:"lastLoginMethod,omitempty"`
		entity.ExtraContainer
	}

	// ChangePasswordParams defines the payload for password change requests.
	ChangePasswordParams struct {
		UserID          string `json:"userId"`
		CurrentPassword string `json:"currentPassword" binding:"required"`
		NewPassword     string `json:"newPassword" binding:"required,min=6"`
		entity.ExtraContainer
	}

	// SendVerificationEmailParams defines the payload for requesting an email verification link or token.
	SendVerificationEmailParams struct {
		Email string `json:"email" binding:"required,email"`
		entity.ExtraContainer
	}

	// VerifyEmailParams defines the token payload for email verification.
	VerifyEmailParams struct {
		Token string `json:"token" binding:"required"`
		entity.ExtraContainer
	}

	// VerifyPasswordParams defines the payload for checking if the provided password matches the user's current password.
	VerifyPasswordParams struct {
		UserID   string `json:"userId" binding:"required"`
		Password string `json:"password" binding:"required"`
		entity.ExtraContainer
	}

	// ForgotPasswordParams defines the payload for requesting a password reset email.
	ForgotPasswordParams struct {
		Email string `json:"email" binding:"required,email"`
		entity.ExtraContainer
	}

	// ResetPasswordParams defines the payload for setting a new password using a reset token.
	ResetPasswordParams struct {
		Token       string `json:"token" binding:"required"`
		NewPassword string `json:"newPassword" binding:"required,min=6"`
		entity.ExtraContainer
	}

	// CreateUserParams defines the mutable parameter payload passed to repository user creation operations.
	CreateUserParams struct {
		Email           string  `json:"email"`
		PasswordHash    string  `json:"-"`
		Name            string  `json:"name"`
		Role            string  `json:"role,omitempty"`
		LastLoginMethod *string `json:"lastLoginMethod,omitempty"`
		entity.ExtraContainer
	}
)
