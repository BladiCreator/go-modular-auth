package store

import (
	"context"
	"encoding/base64"
	"errors"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

var (
	// ErrNotFound is returned when a passkey record does not exist.
	ErrNotFound = errors.New("store: passkey credential not found")

	// ErrConflict is returned when attempting to insert an already existing credential ID.
	ErrConflict = errors.New("store: passkey credential already exists")
)

// Credential represents a WebAuthn / FIDO2 credential registered by a user.
type Credential struct {
	// ID is the base64url-encoded string representation of CredentialID.
	ID string `json:"id"`

	// CredentialID is the raw byte identifier of the public key credential source.
	CredentialID []byte `json:"credential_id"`

	// UserID is the foreign key linking this passkey to the core user identity.
	UserID string `json:"user_id"`

	// FriendlyName is an optional human-readable name for the authenticator (e.g., "Work MacBook").
	FriendlyName string `json:"friendly_name"`

	// PublicKey is the raw COSE public key byte sequence.
	PublicKey []byte `json:"public_key"`

	// AttestationType is the attestation format recorded during registration.
	AttestationType string `json:"attestation_type"`

	// AAGUID is the Authenticator Attestation GUID.
	AAGUID []byte `json:"aaguid"`

	// SignCount is the signature counter used for replay and clone detection.
	SignCount uint32 `json:"sign_count"`

	// CloneWarning indicates whether a counter regression was detected during authentication.
	CloneWarning bool `json:"clone_warning"`

	// Attachment indicates platform vs cross-platform authenticator attachment.
	Attachment protocol.AuthenticatorAttachment `json:"attachment"`

	// Transports lists supported communication channels (usb, nfc, ble, internal, hybrid).
	Transports []protocol.AuthenticatorTransport `json:"transports"`

	// UserPresent flags whether user presence was verified.
	UserPresent bool `json:"user_present"`

	// UserVerified flags whether user verification (PIN, biometric) was performed.
	UserVerified bool `json:"user_verified"`

	// BackupEligible indicates whether the passkey is eligible for multi-device sync/backup.
	BackupEligible bool `json:"backup_eligible"`

	// BackupState indicates whether the passkey is currently synced/backed up.
	BackupState bool `json:"backup_state"`

	// CreatedAt records credential registration timestamp.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt records metadata or sign counter update timestamp.
	UpdatedAt time.Time `json:"updated_at"`

	// LastUsedAt records the most recent successful authentication timestamp.
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`

	// RevokedAt records revocation timestamp if revoked.
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// Active reports whether the passkey has not been revoked.
func (c *Credential) Active() bool {
	return c.RevokedAt == nil
}

// ToWebAuthn converts a store Credential into a webauthn.Credential instance.
func (c *Credential) ToWebAuthn() webauthn.Credential {
	return webauthn.Credential{
		ID:              c.CredentialID,
		PublicKey:       c.PublicKey,
		AttestationType: c.AttestationType,
		Transport:       c.Transports,
		Flags: webauthn.CredentialFlags{
			UserPresent:    c.UserPresent,
			UserVerified:   c.UserVerified,
			BackupEligible: c.BackupEligible,
			BackupState:    c.BackupState,
		},
		Authenticator: webauthn.Authenticator{
			AAGUID:       c.AAGUID,
			SignCount:    c.SignCount,
			CloneWarning: c.CloneWarning,
			Attachment:   c.Attachment,
		},
	}
}

// FromWebAuthn constructs a store Credential from a validated webauthn.Credential.
func FromWebAuthn(userID, friendlyName string, cred *webauthn.Credential, now time.Time) *Credential {
	return &Credential{
		ID:              base64.RawURLEncoding.EncodeToString(cred.ID),
		CredentialID:    cred.ID,
		UserID:          userID,
		FriendlyName:    friendlyName,
		PublicKey:       cred.PublicKey,
		AttestationType: cred.AttestationType,
		AAGUID:          cred.Authenticator.AAGUID,
		SignCount:       cred.Authenticator.SignCount,
		CloneWarning:    cred.Authenticator.CloneWarning,
		Attachment:      cred.Authenticator.Attachment,
		Transports:      cred.Transport,
		UserPresent:     cred.Flags.UserPresent,
		UserVerified:    cred.Flags.UserVerified,
		BackupEligible:  cred.Flags.BackupEligible,
		BackupState:     cred.Flags.BackupState,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
}

// Store is the persistence contract for passkey credentials.
type Store interface {
	// SaveCredential persists a newly registered passkey credential.
	// Returns ErrConflict if the CredentialID already exists.
	SaveCredential(ctx context.Context, c *Credential) error

	// GetCredentialByID retrieves a passkey by its raw credential ID.
	// Returns ErrNotFound if missing.
	GetCredentialByID(ctx context.Context, credentialID []byte) (*Credential, error)

	// ListCredentialsByUser returns all active (non-revoked) passkeys for a user.
	ListCredentialsByUser(ctx context.Context, userID string) ([]*Credential, error)

	// UpdateCredential updates mutable metadata (friendly name, sign count, last used at, clone warning).
	UpdateCredential(ctx context.Context, c *Credential) error

	// DeleteCredential removes or permanently revokes a credential by its raw ID.
	DeleteCredential(ctx context.Context, credentialID []byte) error
}
