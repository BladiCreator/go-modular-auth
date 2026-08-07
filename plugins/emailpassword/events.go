package emailpassword

import (
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

const (
	// EventSignUpBefore is emitted right before creating a new user record.
	// Payload: *SignUpEventPayload
	EventSignUpBefore = "emailpassword:signup:before"

	// EventSignUpAfter is emitted immediately after successfully registering a user and their account.
	// Payload: *SignUpEventPayload
	EventSignUpAfter = "emailpassword:signup:after"

	// EventSignInBefore is emitted before validating credentials during sign-in.
	// Payload: *SignInEventPayload
	EventSignInBefore = "emailpassword:signin:before"

	// EventSignInAfter is emitted after successfully verifying user credentials.
	// Payload: *SignInEventPayload
	EventSignInAfter = "emailpassword:signin:after"

	// EventPasswordChangeBefore is emitted before updating a user's password.
	// Payload: *PasswordChangeEventPayload
	EventPasswordChangeBefore = "emailpassword:password_change:before"

	// EventPasswordChangeAfter is emitted after successfully updating a user's password.
	// Payload: *PasswordChangeEventPayload
	EventPasswordChangeAfter = "emailpassword:password_change:after"

	// EventPasswordResetRequested is emitted when generating a password reset token.
	// Useful for sending notification emails.
	// Payload: *PasswordResetRequestedEventPayload
	EventPasswordResetRequested = "emailpassword:password_reset:requested"

	// EventPasswordResetCompleted is emitted after changing a password using a valid token.
	// Payload: *PasswordResetCompletedEventPayload
	EventPasswordResetCompleted = "emailpassword:password_reset:completed"
)

// SignUpEventPayload contains the data associated with a sign-up event.
type SignUpEventPayload struct {
	Params *dto.CreateUserParams
	User   *entity.User
}

// SignInEventPayload contains the data associated with a sign-in event.
type SignInEventPayload struct {
	User *entity.User
}

// PasswordChangeEventPayload contains the data for a password change event.
type PasswordChangeEventPayload struct {
	UserID string
}

// PasswordResetRequestedEventPayload contains the details for sending a password reset email.
type PasswordResetRequestedEventPayload struct {
	User      *entity.User
	Token     string
	ExpiresAt time.Time
}

// PasswordResetCompletedEventPayload contains confirmation of password reset completion.
type PasswordResetCompletedEventPayload struct {
	UserID string
}
