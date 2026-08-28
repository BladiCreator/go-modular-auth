package username

// Standard Event names for the Username plugin.
const (
	// EventSignInBefore is published before authenticating with username credentials.
	EventSignInBefore = "username:signin:before"

	// EventSignInAfter is published after successful authentication with username credentials.
	EventSignInAfter = "username:signin:after"

	// EventUpdateBefore is published before updating a user's username.
	EventUpdateBefore = "username:update:before"

	// EventUpdateAfter is published after updating a user's username.
	EventUpdateAfter = "username:update:after"
)
