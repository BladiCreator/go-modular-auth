package passkey

import (
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/plugin"
	"github.com/go-webauthn/webauthn/protocol"
)

// Request & Response DTOs
type (
	// GenerateRegistrationOptionsParams holds inputs for creating a WebAuthn credential registration ceremony challenge.
	GenerateRegistrationOptionsParams struct {
		UserID                  string                             `json:"userId,omitempty"`
		UserName                string                             `json:"userName,omitempty"`
		UserDisplayName         string                             `json:"userDisplayName,omitempty"`
		AuthenticatorAttachment *protocol.AuthenticatorAttachment `json:"authenticatorAttachment,omitempty"`
		Context                 *string                            `json:"context,omitempty"`
		CustomName              *string                            `json:"customName,omitempty"`
		plugin.ExtraContainer
	}

	// RegistrationOptionsResult contains creation options sent to the browser and the associated challenge token.
	RegistrationOptionsResult struct {
		Options        *protocol.CredentialCreation `json:"options"`
		ChallengeToken string                       `json:"challengeToken"`
		ExpiresAt      time.Time                    `json:"expiresAt"`
	}

	// VerifyRegistrationParams holds data returned from navigator.credentials.create() for verification.
	VerifyRegistrationParams struct {
		ChallengeToken string                               `json:"challengeToken"`
		Origin         string                               `json:"origin,omitempty"`
		Response       *protocol.CredentialCreationResponse `json:"response"`
		Name           *string                              `json:"name,omitempty"`
		CallerUserID   *string                              `json:"callerUserId,omitempty"`
		plugin.ExtraContainer
	}

	// GenerateAuthenticationOptionsParams holds inputs for creating a WebAuthn assertion ceremony challenge.
	GenerateAuthenticationOptionsParams struct {
		UserID *string `json:"userId,omitempty"` // Optional. Omit for discoverable/resident key/autofill login.
		plugin.ExtraContainer
	}

	// AuthenticationOptionsResult contains assertion request options and the tracking challenge token.
	AuthenticationOptionsResult struct {
		Options        *protocol.CredentialAssertion `json:"options"`
		ChallengeToken string                        `json:"challengeToken"`
		ExpiresAt      time.Time                     `json:"expiresAt"`
	}

	// VerifyAuthenticationParams holds data returned from navigator.credentials.get() for verification.
	VerifyAuthenticationParams struct {
		ChallengeToken string                                `json:"challengeToken"`
		Origin         string                                `json:"origin,omitempty"`
		Response       *protocol.CredentialAssertionResponse `json:"response"`
		plugin.ExtraContainer
	}

	// VerifyAuthenticationResult contains authenticated identity, issued session, and the verified passkey.
	VerifyAuthenticationResult struct {
		User    *entity.User    `json:"user"`
		Session *entity.Session `json:"session"`
		Passkey *entity.Passkey `json:"passkey"`
	}

	// ListPasskeysParams filters passkeys for a specific user.
	ListPasskeysParams struct {
		UserID string `json:"userId"`
		plugin.ExtraContainer
	}

	// UpdatePasskeyParams contains update parameters for an existing passkey.
	UpdatePasskeyParams struct {
		ID           string `json:"id"`
		CallerUserID string `json:"callerUserId"`
		Name         string `json:"name"`
		plugin.ExtraContainer
	}

	// DeletePasskeyParams contains deletion parameters for an existing passkey.
	DeletePasskeyParams struct {
		ID           string `json:"id"`
		CallerUserID string `json:"callerUserId"`
		plugin.ExtraContainer
	}
)
