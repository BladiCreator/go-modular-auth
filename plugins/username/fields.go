package username

// Standard Extra metadata keys and field names for the Username plugin.
const (
	FieldUsername        = "username"
	FieldDisplayUsername = "display_username"

	ExtraKeyUsername        = "username"
	ExtraKeyDisplayUsername = "display_username"
)

// Standard Event names for the Username plugin.
const (
	EventSignInBefore = "user.signin.username.before"
	EventSignInAfter  = "user.signin.username.after"

	EventUpdateBefore = "user.update.username.before"
	EventUpdateAfter  = "user.update.username.after"
)
