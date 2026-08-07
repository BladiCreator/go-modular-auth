// Package emailpassword defines event constants and typed event payloads published by the EmailPassword plugin.
package emailpassword

import (
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

const (
	// EventSignUpBefore is emitted right before persisting a new user record.
	// Event listeners can inspect and mutate parameters (e.g. payload.Params.Set("role", "admin")).
	// Payload: *SignUpEventPayload
	EventSignUpBefore = "emailpassword:signup:before"

	// EventSignUpAfter is emitted immediately after successfully registering a user and creating their credential account.
	// Useful for triggering asynchronous welcome emails or provisioning external services.
	// Payload: *SignUpEventPayload
	EventSignUpAfter = "emailpassword:signup:after"

	// EventSignInBefore is emitted before validating credentials during sign-in.
	// Payload: *SignInEventPayload
	EventSignInBefore = "emailpassword:signin:before"

	// EventSignInAfter is emitted after successfully verifying user credentials and establishing a session.
	// Useful for security audit logs, geo-IP notifications, or analytics tracking.
	// Payload: *SignInEventPayload
	EventSignInAfter = "emailpassword:signin:after"

	// EventPasswordChangeBefore is emitted before updating a user's password.
	// Payload: *PasswordChangeEventPayload
	EventPasswordChangeBefore = "emailpassword:password_change:before"

	// EventPasswordChangeAfter is emitted after successfully updating a user's password in storage.
	// Payload: *PasswordChangeEventPayload
	EventPasswordChangeAfter = "emailpassword:password_change:after"

	// EventPasswordResetRequested is emitted when a secure password reset token is generated.
	// Essential for dispatching password reset emails containing the verification token link.
	// Payload: *PasswordResetRequestedEventPayload
	EventPasswordResetRequested = "emailpassword:password_reset:requested"

	// EventPasswordResetCompleted is emitted after a password has been successfully reset using a valid token.
	// Useful for sending security confirmation notifications.
	// Payload: *PasswordResetCompletedEventPayload
	EventPasswordResetCompleted = "emailpassword:password_reset:completed"
)

// SignUpEventPayload contains the parameter and entity data associated with a sign-up event.
type SignUpEventPayload struct {
	// Params holds mutable user creation parameters (including dynamic Extra metadata).
	Params *dto.CreateUserParams

	// User contains the persisted user entity (populated in EventSignUpAfter).
	User *entity.User
}

// SignInEventPayload contains the authenticated user entity associated with a sign-in event.
type SignInEventPayload struct {
	// User is the authenticated user entity.
	User *entity.User
}

// PasswordChangeEventPayload contains the user identifier for password change lifecycle events.
type PasswordChangeEventPayload struct {
	// UserID identifies the user whose password is being modified.
	UserID string
}

// PasswordResetRequestedEventPayload contains details required to dispatch a password reset email to a user.
type PasswordResetRequestedEventPayload struct {
	// User is the target user entity requesting the reset.
	User *entity.User

	// Token is the secure random token generated for the password reset request.
	Token string

	// ExpiresAt specifies the exact expiration time for the reset token.
	ExpiresAt time.Time
}

// PasswordResetCompletedEventPayload contains confirmation details after a password reset has completed.
type PasswordResetCompletedEventPayload struct {
	// UserID identifies the user whose password was reset.
	UserID string
}
