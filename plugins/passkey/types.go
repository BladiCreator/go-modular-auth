package passkey

import (
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/go-webauthn/webauthn/protocol"
)

// Request & Response DTOs
type (
	// GenerateRegistrationOptionsParams holds inputs for creating a WebAuthn credential registration ceremony challenge.
	GenerateRegistrationOptionsParams struct {
		UserID                  string                            `json:"userId,omitzero"`
		UserName                string                            `json:"userName,omitzero"`
		UserDisplayName         string                            `json:"userDisplayName,omitzero"`
		AuthenticatorAttachment *protocol.AuthenticatorAttachment `json:"authenticatorAttachment,omitzero"`
		Context                 *string                           `json:"context,omitzero"`
		CustomName              *string                           `json:"customName,omitzero"`
		Extra                   map[string]any                    `json:"extra,omitzero"`
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
		Origin         string                               `json:"origin,omitzero"`
		Response       *protocol.CredentialCreationResponse `json:"response"`
		Name           *string                              `json:"name,omitzero"`
		CallerUserID   *string                              `json:"callerUserId,omitzero"`
		Extra          map[string]any                       `json:"extra,omitzero"`
	}

	// GenerateAuthenticationOptionsParams holds inputs for creating a WebAuthn assertion ceremony challenge.
	GenerateAuthenticationOptionsParams struct {
		UserID *string        `json:"userId,omitzero"` // Optional. Omit for discoverable/resident key/autofill login.
		Extra  map[string]any `json:"extra,omitzero"`
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
		Origin         string                                `json:"origin,omitzero"`
		Response       *protocol.CredentialAssertionResponse `json:"response"`
		IPAddress      string                                `json:"ipAddress,omitzero"`
		UserAgent      string                                `json:"userAgent,omitzero"`
		Extra          map[string]any                        `json:"extra,omitzero"`
	}

	// VerifyAuthenticationResult contains authenticated identity, issued session, and the verified passkey.
	VerifyAuthenticationResult struct {
		User    *entity.User    `json:"user"`
		Session *entity.Session `json:"session"`
		Passkey *entity.Passkey `json:"passkey"`
	}

	// ListPasskeysParams filters passkeys for a specific user.
	ListPasskeysParams struct {
		UserID string         `json:"userId"`
		Extra  map[string]any `json:"extra,omitzero"`
	}

	// UpdatePasskeyParams contains update parameters for an existing passkey.
	UpdatePasskeyParams struct {
		ID           string         `json:"id"`
		CallerUserID string         `json:"callerUserId"`
		Name         string         `json:"name"`
		Extra        map[string]any `json:"extra,omitzero"`
	}

	// DeletePasskeyParams contains deletion parameters for an existing passkey.
	DeletePasskeyParams struct {
		ID           string         `json:"id"`
		CallerUserID string         `json:"callerUserId"`
		Extra        map[string]any `json:"extra,omitzero"`
	}
)
