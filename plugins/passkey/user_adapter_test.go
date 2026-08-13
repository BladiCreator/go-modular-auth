package passkey

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

func TestWebAuthnUserAdapter_Internals(t *testing.T) {
	transports := "usb,nfc"
	aaguid := "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4"

	pk := &entity.Passkey{
		ID:           "pk_adapt_1",
		UserID:       "usr_adapt",
		CredentialID: base64.RawURLEncoding.EncodeToString([]byte("cred_raw_bytes")),
		PublicKey:    base64.StdEncoding.EncodeToString([]byte("pub_raw_bytes")),
		Counter:      42,
		DeviceType:   "multiDevice",
		BackedUp:     true,
		Transports:   &transports,
		AAGUID:       &aaguid,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	user := buildWebAuthnUser("usr_adapt", "adapt@example.com", "Adapt User", []*entity.Passkey{pk})

	if string(user.WebAuthnID()) != "usr_adapt" {
		t.Errorf("WebAuthnID mismatch: %s", string(user.WebAuthnID()))
	}
	if user.WebAuthnName() != "adapt@example.com" {
		t.Errorf("WebAuthnName mismatch: %s", user.WebAuthnName())
	}
	if user.WebAuthnDisplayName() != "Adapt User" {
		t.Errorf("WebAuthnDisplayName mismatch: %s", user.WebAuthnDisplayName())
	}
	if user.WebAuthnIcon() != "" {
		t.Errorf("WebAuthnIcon should be empty")
	}

	creds := user.WebAuthnCredentials()
	if len(creds) != 1 {
		t.Fatalf("Expected 1 credential, got %d", len(creds))
	}

	cred := creds[0]
	if string(cred.ID) != "cred_raw_bytes" {
		t.Errorf("Credential ID bytes mismatch: %s", string(cred.ID))
	}
	if string(cred.PublicKey) != "pub_raw_bytes" {
		t.Errorf("Credential PublicKey bytes mismatch: %s", string(cred.PublicKey))
	}
	if cred.Authenticator.SignCount != 42 {
		t.Errorf("SignCount mismatch: %d", cred.Authenticator.SignCount)
	}
	if !cred.Flags.BackupEligible || !cred.Flags.BackupState {
		t.Errorf("Backup flags mismatch: %+v", cred.Flags)
	}
	if len(cred.Transport) != 2 {
		t.Errorf("Transport length mismatch: %d", len(cred.Transport))
	}

	formatted := formatAAGUID(cred.Authenticator.AAGUID)
	if formatted != aaguid {
		t.Errorf("AAGUID format mismatch: got %s, want %s", formatted, aaguid)
	}
}

func TestAAGUID_Formatting_EdgeCases(t *testing.T) {
	// Anonymous all zero
	zeroBytes := make([]byte, 16)
	if formatAAGUID(zeroBytes) != AnonymousAAGUID {
		t.Errorf("Expected AnonymousAAGUID for zero bytes")
	}

	// Empty bytes
	if formatAAGUID([]byte{}) != AnonymousAAGUID {
		t.Errorf("Expected AnonymousAAGUID for empty bytes")
	}

	// Non-16 bytes
	customBytes := []byte{0x01, 0x02, 0x03}
	if formatAAGUID(customBytes) != "010203" {
		t.Errorf("Expected hex string for custom short slice, got %s", formatAAGUID(customBytes))
	}

	// Parse nil
	parsed := parseAAGUIDBytes(nil)
	if len(parsed) != 16 {
		t.Fatalf("Expected 16 bytes for nil AAGUID")
	}
}

func TestDecodeBase64Flexible(t *testing.T) {
	raw := []byte("hello_fido2_webauthn_passkey_test")

	// 1. StdEncoding
	s1 := base64.StdEncoding.EncodeToString(raw)
	d1, err := decodeBase64Flexible(s1)
	if err != nil || string(d1) != string(raw) {
		t.Errorf("Failed decoding StdEncoding: %v", err)
	}

	// 2. RawStdEncoding
	s2 := base64.RawStdEncoding.EncodeToString(raw)
	d2, err := decodeBase64Flexible(s2)
	if err != nil || string(d2) != string(raw) {
		t.Errorf("Failed decoding RawStdEncoding: %v", err)
	}

	// 3. URLEncoding
	s3 := base64.URLEncoding.EncodeToString(raw)
	d3, err := decodeBase64Flexible(s3)
	if err != nil || string(d3) != string(raw) {
		t.Errorf("Failed decoding URLEncoding: %v", err)
	}

	// 4. RawURLEncoding
	s4 := base64.RawURLEncoding.EncodeToString(raw)
	d4, err := decodeBase64Flexible(s4)
	if err != nil || string(d4) != string(raw) {
		t.Errorf("Failed decoding RawURLEncoding: %v", err)
	}
}
