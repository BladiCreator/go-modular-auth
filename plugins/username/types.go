package username

import (
	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/plugin"
)

// DTO Parameter and Result Structs

// SignInUsernameParams defines input parameters to authenticate a user using username and password.
type SignInUsernameParams struct {
	// Username is the target account username (required).
	Username string `json:"username"`

	// Password is the plain text user password (required).
	Password string `json:"password"`

	// RememberMe extends session lifespan if true.
	RememberMe *bool `json:"remember_me,omitempty"`

	plugin.ExtraContainer
}

// SignInUsernameResult contains the authenticated user entity and session details.
type SignInUsernameResult struct {
	// User is the authenticated user entity.
	User *entity.User `json:"user"`

	// SessionToken is the raw unique session token string.
	SessionToken string `json:"session_token"`

	// Session is the persisted active session entity.
	Session *entity.Session `json:"session"`
}

// IsUsernameAvailableParams defines parameters to check if a username is free for registration.
type IsUsernameAvailableParams struct {
	// Username is the username candidate to check.
	Username string `json:"username"`

	plugin.ExtraContainer
}

// IsUsernameAvailableResult reports username availability.
type IsUsernameAvailableResult struct {
	// Available indicates whether the queried username is free.
	Available bool `json:"available"`

	// Username is the processed username being queried.
	Username string `json:"username"`
}

// UpdateUsernameParams defines parameters to update a user's username and display_username.
type UpdateUsernameParams struct {
	// UserID is the unique identifier of the user (required).
	UserID string `json:"user_id"`

	// Username is the new username string (required).
	Username string `json:"username"`

	// DisplayUsername is the optional display username (defaults to Username if empty).
	DisplayUsername string `json:"display_username,omitempty"`

	plugin.ExtraContainer
}

// UpdateUsernameResult reports the result of updating a username.
type UpdateUsernameResult struct {
	// Success indicates if the username update completed successfully.
	Success bool `json:"success"`

	// User is the updated user entity.
	User *entity.User `json:"user"`
}
