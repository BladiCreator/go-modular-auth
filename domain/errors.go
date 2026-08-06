// Package domain defines core domain entities, data transfer objects (DTOs), and sentinel errors.
package domain

import "errors"

var (
	// User domain errors
	ErrUserNotFound       = errors.New("AuthService: user not found")
	ErrEmailAlreadyInUse  = errors.New("AuthService: email already in use")
	ErrInvalidCredentials = errors.New("AuthService: invalid credentials")
	ErrPasswordTooShort   = errors.New("AuthService: password too short")

	// Session domain errors
	ErrSessionNotFound = errors.New("AuthService: session not found")
	ErrSessionExpired  = errors.New("AuthService: session expired")

	// 2FA domain errors
	ErrTOTPNotFound       = errors.New("AuthService: totp secret not found")
	ErrTOTPAlreadyEnabled = errors.New("AuthService: totp already enabled")
	ErrTOTPNotEnabled     = errors.New("AuthService: totp not enabled")
	ErrInvalidTOTP        = errors.New("AuthService: invalid totp code")
)
