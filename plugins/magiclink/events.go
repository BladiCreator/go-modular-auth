package magiclink

import (
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

// Event bus topic string constants emitted during Magic Link lifecycle operations.
const (
	// EventMagicLinkSendBefore is emitted right before dispatching a magic link email.
	// Payload: *SendMagicLinkPendingPayload
	EventMagicLinkSendBefore = "magiclink:send:before"

	// EventMagicLinkSent is emitted immediately after a magic link email has been dispatched.
	// Payload: *MagicLinkSentPayload
	EventMagicLinkSent = "magiclink:send:after"

	// EventMagicLinkVerifyBefore is emitted right before verifying a submitted magic link token.
	// Payload: *VerifyBeforePayload
	EventMagicLinkVerifyBefore = "magiclink:verify:before"

	// EventMagicLinkVerified is emitted after a magic link token has been successfully verified.
	// Payload: *MagicLinkVerifiedPayload
	EventMagicLinkVerified = "magiclink:verify:after"

	// EventMagicLinkSignInSuccess is emitted when a user successfully authenticates or registers via magic link.
	// Payload: *SignInSuccessPayload
	EventMagicLinkSignInSuccess = "magiclink:sign_in:success"

	// EventMagicLinkFailed is emitted when an invalid magic link token is submitted or verification fails.
	// Payload: *MagicLinkFailedPayload
	EventMagicLinkFailed = "magiclink:verify:failed"

	// EventMagicLinkExpired is emitted when verification is attempted on an expired magic link token.
	// Payload: *MagicLinkFailedPayload
	EventMagicLinkExpired = "magiclink:expired"
)

// Typed Event Payloads
type (
	// SendMagicLinkPendingPayload contains recipient and expiration details before dispatching a magic link.
	SendMagicLinkPendingPayload struct {
		Email     string         `json:"email"`
		URL       string         `json:"url"`
		ExpiresAt time.Time      `json:"expires_at"`
		Extra     map[string]any `json:"extra,omitempty"`
	}

	// MagicLinkSentPayload contains confirmation details after dispatching a magic link email.
	MagicLinkSentPayload struct {
		Email     string         `json:"email"`
		URL       string         `json:"url"`
		ExpiresAt time.Time      `json:"expires_at"`
		Extra     map[string]any `json:"extra,omitempty"`
	}

	// VerifyBeforePayload contains the raw token and extra parameters before verification execution.
	VerifyBeforePayload struct {
		Token string         `json:"token"`
		Extra map[string]any `json:"extra,omitempty"`
	}

	// MagicLinkVerifiedPayload contains verified user and token details.
	MagicLinkVerifiedPayload struct {
		Email     string       `json:"email"`
		User      *entity.User `json:"user"`
		IsNewUser bool         `json:"is_new_user"`
	}

	// SignInSuccessPayload contains authentication output upon successful magic link login.
	SignInSuccessPayload struct {
		User      *entity.User    `json:"user"`
		Session   *entity.Session `json:"session"`
		IsNewUser bool            `json:"is_new_user"`
	}

	// MagicLinkFailedPayload contains failure context when magic link verification fails.
	MagicLinkFailedPayload struct {
		Email  string         `json:"email,omitempty"`
		Token  string         `json:"token,omitempty"`
		Reason string         `json:"reason"`
		Extra  map[string]any `json:"extra,omitempty"`
	}
)
