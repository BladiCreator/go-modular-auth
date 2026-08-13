package passkey_test

import (
	"testing"

	"github.com/BladiCreator/go-modular-auth/plugins/passkey"
)

func TestGetAuthenticatorName(t *testing.T) {
	tests := []struct {
		name     string
		aaguid   *string
		expected string
	}{
		{
			name:     "Nil AAGUID",
			aaguid:   nil,
			expected: "Passkey",
		},
		{
			name:     "Empty AAGUID",
			aaguid:   ptr(""),
			expected: "Passkey",
		},
		{
			name:     "Anonymous AAGUID",
			aaguid:   ptr(passkey.AnonymousAAGUID),
			expected: "Passkey",
		},
		{
			name:     "Google Password Manager (exact)",
			aaguid:   ptr("ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4"),
			expected: "Google Password Manager",
		},
		{
			name:     "Apple Passwords (uppercase)",
			aaguid:   ptr("FBFC3007-154E-4ECC-8C0B-6E020557D7BD"),
			expected: "Apple Passwords",
		},
		{
			name:     "Windows Hello with whitespace",
			aaguid:   ptr("  08987058-cadc-4b81-b6e1-30de50dcbe96  "),
			expected: "Windows Hello",
		},
		{
			name:     "1Password",
			aaguid:   ptr("bada5566-a7aa-401f-bd96-45619a55120d"),
			expected: "1Password",
		},
		{
			name:     "Bitwarden",
			aaguid:   ptr("d548826e-79b4-db40-a3d8-11116f7e8349"),
			expected: "Bitwarden",
		},
		{
			name:     "YubiKey 5 Series",
			aaguid:   ptr("cb69481e-8ff7-4039-93ec-0a2729a1ef67"),
			expected: "YubiKey 5 Series",
		},
		{
			name:     "Unknown valid AAGUID returns Passkey fallback",
			aaguid:   ptr("11111111-2222-3333-4444-555555555555"),
			expected: "Passkey",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := passkey.GetAuthenticatorName(tt.aaguid)
			if got != tt.expected {
				t.Errorf("GetAuthenticatorName(%v) = %q, want %q", tt.aaguid, got, tt.expected)
			}
		})
	}
}

func ptr(s string) *string {
	return &s
}
