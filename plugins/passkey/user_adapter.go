package passkey

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// webAuthnUser adapts application user models and passkeys to satisfy the webauthn.User interface.
type webAuthnUser struct {
	id          string
	name        string
	displayName string
	credentials []webauthn.Credential
}

func (u *webAuthnUser) WebAuthnID() []byte {
	return []byte(u.id)
}

func (u *webAuthnUser) WebAuthnName() string {
	if u.name != "" {
		return u.name
	}
	return u.id
}

func (u *webAuthnUser) WebAuthnDisplayName() string {
	if u.displayName != "" {
		return u.displayName
	}
	if u.name != "" {
		return u.name
	}
	return u.id
}

func (u *webAuthnUser) WebAuthnIcon() string {
	return ""
}

func (u *webAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.credentials
}

// buildWebAuthnUser creates a webauthn.User implementation from user info and stored passkeys.
func buildWebAuthnUser(userID, name, displayName string, passkeys []*entity.Passkey) *webAuthnUser {
	creds := make([]webauthn.Credential, 0, len(passkeys))
	for _, pk := range passkeys {
		if cred, err := passkeyToCredential(pk); err == nil {
			creds = append(creds, cred)
		}
	}
	return &webAuthnUser{
		id:          userID,
		name:        name,
		displayName: displayName,
		credentials: creds,
	}
}

// passkeyToCredential converts a domain entity.Passkey to a webauthn.Credential.
func passkeyToCredential(pk *entity.Passkey) (webauthn.Credential, error) {
	credID, err := decodeBase64Flexible(pk.CredentialID)
	if err != nil {
		return webauthn.Credential{}, err
	}

	pubKey, err := decodeBase64Flexible(pk.PublicKey)
	if err != nil {
		return webauthn.Credential{}, err
	}

	var transports []protocol.AuthenticatorTransport
	if pk.Transports != nil && *pk.Transports != "" {
		parts := strings.Split(*pk.Transports, ",")
		for _, p := range parts {
			t := strings.TrimSpace(p)
			if t != "" {
				transports = append(transports, protocol.AuthenticatorTransport(t))
			}
		}
	}

	aaguidBytes := parseAAGUIDBytes(pk.AAGUID)

	cred := webauthn.Credential{
		ID:              credID,
		PublicKey:       pubKey,
		AttestationType: "none",
		Transport:       transports,
		Flags: webauthn.CredentialFlags{
			BackupEligible: pk.DeviceType == "multiDevice",
			BackupState:    pk.BackedUp,
		},
		Authenticator: webauthn.Authenticator{
			AAGUID:    aaguidBytes,
			SignCount: pk.Counter,
		},
	}

	return cred, nil
}

// formatAAGUID formats a 16-byte AAGUID slice into a standard canonical UUID string.
func formatAAGUID(aaguid []byte) string {
	if len(aaguid) != 16 {
		if len(aaguid) == 0 {
			return AnonymousAAGUID
		}
		return hex.EncodeToString(aaguid)
	}
	// Check if all zero
	allZero := true
	for _, b := range aaguid {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return AnonymousAAGUID
	}

	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		aaguid[0:4], aaguid[4:6], aaguid[6:8], aaguid[8:10], aaguid[10:16])
}

// parseAAGUIDBytes parses a canonical UUID string or hex string into a 16-byte slice.
func parseAAGUIDBytes(aaguidStr *string) []byte {
	if aaguidStr == nil || *aaguidStr == "" || *aaguidStr == AnonymousAAGUID {
		return make([]byte, 16)
	}
	clean := strings.ReplaceAll(*aaguidStr, "-", "")
	bytes, err := hex.DecodeString(clean)
	if err != nil || len(bytes) != 16 {
		return make([]byte, 16)
	}
	return bytes
}

// decodeBase64Flexible decodes a string using URL base64, raw URL base64, standard base64, or raw standard base64.
func decodeBase64Flexible(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.StdEncoding.DecodeString(s)
}
