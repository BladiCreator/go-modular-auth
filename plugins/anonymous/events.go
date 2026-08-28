package anonymous

import (
	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

const (
	// EventSignInAnonymousBefore is dispatched prior to creating an anonymous user and session.
	EventSignInAnonymousBefore = "anonymous:sign_in:before"

	// EventSignInAnonymousAfter is dispatched immediately after successfully creating an anonymous user and session.
	EventSignInAnonymousAfter = "anonymous:sign_in:after"

	// EventDeleteAnonymousBefore is dispatched prior to purging an anonymous user and their sessions.
	EventDeleteAnonymousBefore = "anonymous:delete:before"

	// EventDeleteAnonymousAfter is dispatched immediately after purging an anonymous user and their sessions.
	EventDeleteAnonymousAfter = "anonymous:delete:after"

	// EventLinkAccountAfter is dispatched after successfully linking an anonymous account to a new permanent account.
	EventLinkAccountAfter = "anonymous:link_account:after"
)

// SignInAnonymousEventPayload represents the payload broadcasted during anonymous sign-in events.
type SignInAnonymousEventPayload struct {
	User    *entity.User    `json:"user"`
	Session *entity.Session `json:"session"`
}

// DeleteAnonymousEventPayload represents the payload broadcasted during anonymous user deletion events.
type DeleteAnonymousEventPayload struct {
	UserID string `json:"user_id"`
}

// LinkAccountEventPayload represents the payload broadcasted when an anonymous account is linked to a permanent user.
type LinkAccountEventPayload struct {
	Data *OnLinkAccountData `json:"data"`
}
