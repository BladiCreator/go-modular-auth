package passkey

import (
	"context"
	"io"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/go-webauthn/webauthn/protocol"
)

// ProviderPasskey is the provider identifier used when recording linked passkey accounts in Core.
const ProviderPasskey = "passkey"

// BeginRegistrationInput contains options for starting a credential registration ceremony.
type BeginRegistrationInput struct {
	// UserID identifies the user registering a passkey. Required.
	UserID string

	// FriendlyName is an optional human label for the device (e.g. "Pixel 8 Pro").
	FriendlyName string

	// UserVerification overrides the default user verification requirement.
	UserVerification protocol.UserVerificationRequirement

	// ResidentKey overrides the default resident key requirement.
	ResidentKey protocol.ResidentKeyRequirement

	// AuthenticatorAttachment optionally restricts attachment (platform or cross-platform).
	AuthenticatorAttachment protocol.AuthenticatorAttachment
}

// RegistrationOptions represents the registration challenge and public key options for the client.
type RegistrationOptions struct {
	// SessionID is the opaque challenge session identifier used to finish registration.
	SessionID string `json:"session_id"`

	// Options contains the standard WebAuthn PublicKeyCredentialCreationOptions.
	Options *protocol.CredentialCreation `json:"options"`

	// ExpiresAt specifies when the challenge expires.
	ExpiresAt time.Time `json:"expires_at"`
}

// FinishRegistrationInput contains client response data for completing registration.
type FinishRegistrationInput struct {
	// SessionID is the ceremony session ID returned by BeginRegistration. Required.
	SessionID string

	// Response is the raw JSON response payload from navigator.credentials.create().
	Response []byte

	// Body allows streaming the client JSON response directly from a reader.
	Body io.Reader

	// ParsedResponse allows supplying pre-parsed credential creation data.
	ParsedResponse *protocol.ParsedCredentialCreationData

	// FriendlyName optionally overrides the label provided during BeginRegistration.
	FriendlyName string
}

// BeginAuthenticationInput contains options for starting an authentication ceremony.
type BeginAuthenticationInput struct {
	// UserID is optional. If provided, server restricts allowed credentials to this user.
	// If empty, discoverable (usernameless / resident key) authentication is initiated.
	UserID string

	// UserVerification overrides the default user verification requirement.
	UserVerification protocol.UserVerificationRequirement
}

// AuthenticationOptions represents the authentication challenge options for the client.
type AuthenticationOptions struct {
	// SessionID is the opaque challenge session identifier used to finish authentication.
	SessionID string `json:"session_id"`

	// Options contains the standard WebAuthn PublicKeyCredentialRequestOptions.
	Options *protocol.CredentialAssertion `json:"options"`

	// ExpiresAt specifies when the challenge expires.
	ExpiresAt time.Time `json:"expires_at"`
}

// FinishAuthenticationInput contains client response data for completing authentication.
type FinishAuthenticationInput struct {
	// SessionID is the ceremony session ID returned by BeginAuthentication. Required.
	SessionID string

	// Response is the raw JSON response payload from navigator.credentials.get().
	Response []byte

	// Body allows streaming the client JSON response directly from a reader.
	Body io.Reader

	// ParsedResponse allows supplying pre-parsed credential assertion data.
	ParsedResponse *protocol.ParsedCredentialAssertionData

	// Session holds optional IP and User-Agent metadata for the issued core session.
	Session auth.SessionOptions
}

// UpdateCredentialInput holds parameters for updating passkey metadata.
type UpdateCredentialInput struct {
	// UserID verifies ownership. Required.
	UserID string

	// CredentialID is the binary ID of the credential to update. Required.
	CredentialID []byte

	// FriendlyName is the new label for the passkey.
	FriendlyName string
}

// DeleteCredentialInput holds parameters for deleting a passkey.
type DeleteCredentialInput struct {
	// UserID verifies ownership. Required.
	UserID string

	// CredentialID is the binary ID of the credential to delete. Required.
	CredentialID []byte
}

// Passkeys is the strongly typed public capability exposed by this plugin.
// Applications consume it via auth.Get[plugins.Passkeys](a) or auth.Get[passkey.Passkeys](a).
type Passkeys interface {
	// BeginRegistration generates the public key options required by navigator.credentials.create().
	BeginRegistration(ctx context.Context, in BeginRegistrationInput) (*RegistrationOptions, error)

	// FinishRegistration validates the client response, persists the credential, and links the Core account.
	FinishRegistration(ctx context.Context, in FinishRegistrationInput) (*Passkey, error)

	// BeginAuthentication generates the options required by navigator.credentials.get().
	// Supports both user-specified and discoverable (usernameless / resident key) flows.
	BeginAuthentication(ctx context.Context, in BeginAuthenticationInput) (*AuthenticationOptions, error)

	// FinishAuthentication verifies the client assertion, checks sign counter replay protection,
	// and issues an authenticated session via GoModularAuth Core.
	FinishAuthentication(ctx context.Context, in FinishAuthenticationInput) (*auth.AuthResult, error)

	// ListCredentials returns all active passkeys registered to the specified user.
	ListCredentials(ctx context.Context, userID string) ([]*Passkey, error)

	// GetCredential returns a single passkey by credential ID with ownership verification.
	GetCredential(ctx context.Context, userID string, credentialID []byte) (*Passkey, error)

	// UpdateCredential updates metadata (e.g. friendly name) for an existing passkey.
	UpdateCredential(ctx context.Context, in UpdateCredentialInput) (*Passkey, error)

	// DeleteCredential revokes/removes the passkey and cleans up its associated Core account.
	DeleteCredential(ctx context.Context, in DeleteCredentialInput) error
}

// Capability is an alias for Passkeys for idiomatic capability retrieval.
type Capability = Passkeys
