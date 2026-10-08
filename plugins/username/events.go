package username

import auth "github.com/BladiCreator/go-modular-auth"

const (
	// EventCreated is emitted when a username is assigned to a user.
	EventCreated auth.EventName = "username.created"

	// EventUpdated is emitted when an existing username is modified.
	EventUpdated auth.EventName = "username.updated"

	// EventDeleted is emitted when a username assignment is removed.
	EventDeleted auth.EventName = "username.deleted"
)

// CreatedPayload holds observational metadata for EventCreated.
type CreatedPayload struct {
	UserID     string `json:"user_id"`
	Username   string `json:"username"`
	Normalized string `json:"normalized"`
}

// UpdatedPayload holds observational metadata for EventUpdated.
type UpdatedPayload struct {
	UserID        string `json:"user_id"`
	OldUsername   string `json:"old_username"`
	NewUsername   string `json:"new_username"`
	OldNormalized string `json:"old_normalized"`
	NewNormalized string `json:"new_normalized"`
}

// DeletedPayload holds observational metadata for EventDeleted.
type DeletedPayload struct {
	UserID     string `json:"user_id"`
	Username   string `json:"username"`
	Normalized string `json:"normalized"`
}
