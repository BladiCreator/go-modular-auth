package passwordpolicy

import "errors"

var (
	// ErrPasswordTooShort indicates that the password is shorter than the minimum length requirement.
	ErrPasswordTooShort = errors.New("password-policy: password does not meet minimum length requirement")

	// ErrPasswordTooLong indicates that the password exceeds the maximum allowable length.
	ErrPasswordTooLong = errors.New("password-policy: password exceeds maximum length requirement")

	// ErrPasswordRequiresUppercase indicates that the password must contain at least one uppercase letter.
	ErrPasswordRequiresUppercase = errors.New("password-policy: password requires at least one uppercase letter")

	// ErrPasswordRequiresLowercase indicates that the password must contain at least one lowercase letter.
	ErrPasswordRequiresLowercase = errors.New("password-policy: password requires at least one lowercase letter")

	// ErrPasswordRequiresDigit indicates that the password must contain at least one numeric digit.
	ErrPasswordRequiresDigit = errors.New("password-policy: password requires at least one numeric digit")

	// ErrPasswordRequiresSymbol indicates that the password must contain at least one special symbol.
	ErrPasswordRequiresSymbol = errors.New("password-policy: password requires at least one special symbol")

	// ErrPasswordInHistory indicates that the password matches a recently used password in the user's history.
	ErrPasswordInHistory = errors.New("password-policy: password cannot be a recently used password")

	// ErrPasswordCompromised indicates that the password was found in a list of known compromised or breached passwords.
	ErrPasswordCompromised = errors.New("password-policy: password has been identified as compromised or common")

	// ErrInvalidInput indicates that one or more required input arguments are missing or malformed.
	ErrInvalidInput = errors.New("password-policy: invalid input")

	// ErrUserNotFound indicates that the specified user was not found.
	ErrUserNotFound = errors.New("password-policy: user not found")
)
