package lastloginmethod

const (
	// EventLastLoginMethodSet is emitted whenever a user's last login method is successfully updated and stored.
	EventLastLoginMethodSet = "lastloginmethod:set"

	// EventLastLoginMethodCleared is emitted whenever the last login method cookie is cleared.
	EventLastLoginMethodCleared = "lastloginmethod:cleared"
)

// LastLoginMethodEventPayload contains payload data dispatched with last login method lifecycle events.
type LastLoginMethodEventPayload struct {
	UserID       string         `json:"userId,omitempty"`
	Method       string         `json:"method"`
	CookieStored bool           `json:"cookieStored"`
	DBStored     bool           `json:"dbStored"`
	Extra        map[string]any `json:"extra,omitempty"`
}
