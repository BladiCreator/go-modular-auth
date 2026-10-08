package twofactor

import "errors"

var (
	// ErrInvalidInput is returned when required parameters (userID, factorID, code, etc.) are empty or malformed.
	ErrInvalidInput = errors.New("twofactor: invalid input")

	// ErrFactorNotFound is returned when the requested MFA factor does not exist.
	ErrFactorNotFound = errors.New("twofactor: factor not found")

	// ErrFactorAlreadyExists is returned when attempting to enroll an already existing factor.
	ErrFactorAlreadyExists = errors.New("twofactor: factor already exists")

	// ErrFactorAlreadyConfirmed is returned when attempting to confirm an already confirmed factor.
	ErrFactorAlreadyConfirmed = errors.New("twofactor: factor already confirmed")

	// ErrFactorNotConfirmed is returned when attempting to authenticate using an unconfirmed factor.
	ErrFactorNotConfirmed = errors.New("twofactor: factor is not confirmed")

	// ErrInvalidCode is returned when an OTP or recovery code fails verification.
	ErrInvalidCode = errors.New("twofactor: invalid authentication code")

	// ErrReplayDetected is returned when an OTP code has already been consumed for the current or a previous time-step.
	ErrReplayDetected = errors.New("twofactor: replay detected; code already used")

	// ErrChallengeNotFound is returned when an MFA challenge token does not exist.
	ErrChallengeNotFound = errors.New("twofactor: challenge not found")

	// ErrChallengeExpired is returned when an MFA challenge token has passed its expiration time.
	ErrChallengeExpired = errors.New("twofactor: challenge expired")

	// ErrChallengeAlreadyUsed is returned when attempting to verify an already consumed challenge.
	ErrChallengeAlreadyUsed = errors.New("twofactor: challenge already used")

	// ErrNoActiveRecoveryCodes is returned when no active recovery codes remain for the user.
	ErrNoActiveRecoveryCodes = errors.New("twofactor: no active recovery codes available")

	// ErrRecoveryCodeNotFound is returned when the supplied recovery code does not match any active record.
	ErrRecoveryCodeNotFound = errors.New("twofactor: recovery code not found")

	// ErrAssuranceLevelInsufficient is returned when an operation requires AAL2 but the context only holds AAL1.
	ErrAssuranceLevelInsufficient = errors.New("twofactor: assurance level insufficient; AAL2 required")

	// ErrTwoFactorNotEnabled is returned when an operation requires 2FA to be enabled for the user.
	ErrTwoFactorNotEnabled = errors.New("twofactor: two-factor authentication is not enabled")

	// ErrCryptoOperationFailed is returned when secret encryption or decryption fails.
	ErrCryptoOperationFailed = errors.New("twofactor: cryptographic operation failed")
)
