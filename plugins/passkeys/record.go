package passkey

import (
	"encoding/base64"
	"time"

	"github.com/BladiCreator/go-modular-auth/schema"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// Passkey represents a WebAuthn / FIDO2 credential registered by a user.
type Passkey struct {
	ID              string                            `json:"id"`
	CredentialID    []byte                            `json:"credential_id"`
	UserID          string                            `json:"user_id"`
	FriendlyName    string                            `json:"friendly_name"`
	PublicKey       []byte                            `json:"public_key"`
	AttestationType string                            `json:"attestation_type"`
	AAGUID          []byte                            `json:"aaguid"`
	SignCount       uint32                            `json:"sign_count"`
	CloneWarning    bool                              `json:"clone_warning"`
	Attachment      protocol.AuthenticatorAttachment  `json:"attachment"`
	Transports      []protocol.AuthenticatorTransport `json:"transports"`
	UserPresent     bool                              `json:"user_present"`
	UserVerified    bool                              `json:"user_verified"`
	BackupEligible  bool                              `json:"backup_eligible"`
	BackupState     bool                              `json:"backup_state"`
	CreatedAt       time.Time                         `json:"created_at"`
	UpdatedAt       time.Time                         `json:"updated_at"`
	LastUsedAt      *time.Time                        `json:"last_used_at,omitempty"`
	RevokedAt       *time.Time                        `json:"revoked_at,omitempty"`
}

// Active reports whether the passkey has not been revoked.
func (c *Passkey) Active() bool {
	return c.RevokedAt == nil
}

// ToWebAuthn converts a Passkey into a webauthn.Credential instance.
func (c *Passkey) ToWebAuthn() webauthn.Credential {
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

// FromWebAuthn constructs a domain Passkey from a validated webauthn.Credential.
func FromWebAuthn(userID, friendlyName string, cred *webauthn.Credential, now time.Time) *Passkey {
	return &Passkey{
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

const (
	ModelPasskeys = "passkeys"
)

// RegisterSchema registers the passkeys model into the compiled schema.
func RegisterSchema(s *schema.Schema) error {
	m := schema.NewModel(ModelPasskeys, ModelPasskeys, "id")
	_ = m.AddField(schema.Field{Name: "id", Type: schema.TypeString, Required: true})
	_ = m.AddField(schema.Field{Name: "credential_id", Type: schema.TypeBytes, Required: true})
	_ = m.AddField(schema.Field{Name: "user_id", Type: schema.TypeString, Required: true})
	_ = m.AddField(schema.Field{Name: "friendly_name", Type: schema.TypeString})
	_ = m.AddField(schema.Field{Name: "public_key", Type: schema.TypeBytes, Required: true})
	_ = m.AddField(schema.Field{Name: "attestation_type", Type: schema.TypeString})
	_ = m.AddField(schema.Field{Name: "aaguid", Type: schema.TypeBytes})
	_ = m.AddField(schema.Field{Name: "sign_count", Type: schema.TypeInt64, Required: true})
	_ = m.AddField(schema.Field{Name: "clone_warning", Type: schema.TypeBool, Required: true})
	_ = m.AddField(schema.Field{Name: "attachment", Type: schema.TypeString})
	_ = m.AddField(schema.Field{Name: "transports", Type: schema.TypeJSON})
	_ = m.AddField(schema.Field{Name: "user_present", Type: schema.TypeBool, Required: true})
	_ = m.AddField(schema.Field{Name: "user_verified", Type: schema.TypeBool, Required: true})
	_ = m.AddField(schema.Field{Name: "backup_eligible", Type: schema.TypeBool, Required: true})
	_ = m.AddField(schema.Field{Name: "backup_state", Type: schema.TypeBool, Required: true})
	_ = m.AddField(schema.Field{Name: "created_at", Type: schema.TypeTime, Required: true})
	_ = m.AddField(schema.Field{Name: "updated_at", Type: schema.TypeTime, Required: true})
	_ = m.AddField(schema.Field{Name: "last_used_at", Type: schema.TypeTime})
	_ = m.AddField(schema.Field{Name: "revoked_at", Type: schema.TypeTime})

	m.Indexes = []schema.Index{
		{Name: "idx_passkeys_user_id", Fields: []string{"user_id"}},
	}

	return s.AddModel(m)
}
