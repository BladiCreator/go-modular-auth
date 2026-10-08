package passkey_test

import (
	"testing"
	"time"

	passkey "github.com/BladiCreator/go-modular-auth-passkeys"
	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth/store/memory"
	"github.com/go-webauthn/webauthn/protocol"
)

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		opts    []passkey.Option
		wantErr error
	}{
		{
			name: "missing rp display name",
			opts: []passkey.Option{
				passkey.WithRP("localhost", "", []string{"http://localhost:3000"}),
			},
			wantErr: passkey.ErrRPDisplayNameRequired,
		},
		{
			name: "missing rp id",
			opts: []passkey.Option{
				passkey.WithRP("", "Acme", []string{"http://localhost:3000"}),
			},
			wantErr: passkey.ErrRPIDRequired,
		},
		{
			name: "invalid rp id with scheme",
			opts: []passkey.Option{
				passkey.WithRP("https://example.com", "Acme", []string{"https://example.com"}),
			},
			wantErr: passkey.ErrInvalidRPID,
		},
		{
			name: "invalid rp id with path",
			opts: []passkey.Option{
				passkey.WithRP("example.com/api", "Acme", []string{"https://example.com"}),
			},
			wantErr: passkey.ErrInvalidRPID,
		},
		{
			name: "missing origins",
			opts: []passkey.Option{
				passkey.WithRP("example.com", "Acme", nil),
			},
			wantErr: passkey.ErrRPOriginsRequired,
		},
		{
			name: "malformed origin without scheme",
			opts: []passkey.Option{
				passkey.WithRP("example.com", "Acme", []string{"example.com"}),
			},
			wantErr: passkey.ErrInvalidRPOrigin,
		},
		{
			name: "valid configuration",
			opts: []passkey.Option{
				passkey.WithRP("example.com", "Acme", []string{"https://example.com"}),
				passkey.WithTimeout(30 * time.Second),
				passkey.WithUserVerification(protocol.VerificationRequired),
				passkey.WithResidentKey(protocol.ResidentKeyRequirementRequired),
				passkey.WithEnforceSignCounter(true),
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mod := passkey.New(tt.opts...)
			a, err := auth.New(auth.Config{
				Store:   memory.New(),
				Plugins: []auth.PluginModule{mod},
			})

			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tt.wantErr)
				}
				if err != tt.wantErr && !isError(err, tt.wantErr) {
					t.Fatalf("expected error %v, got %v", tt.wantErr, err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if a == nil {
					t.Fatal("expected non-nil auth instance")
				}
			}
		})
	}
}

func isError(err, target error) bool {
	if err == nil || target == nil {
		return err == target
	}
	return err.Error() == target.Error() || (len(err.Error()) >= len(target.Error()) && contains(err.Error(), target.Error()))
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
