package plugin

import (
	"context"

	"github.com/BladiCreator/go-modular-auth/domain/dto"
)

// MFAProvider defines the contract for multi-factor authentication engines (e.g. TwoFactor plugin).
// It decouples primary credential plugins (emailpassword, username, phonenumber) and the core Auth engine
// from concrete plugin implementations.
type MFAProvider interface {
	// RequiresMFA evaluates whether the user must complete an MFA challenge.
	// If the client has supplied an authorized trusted device token,
	// RequiresMFA can verify the device trust and return false to bypass the challenge.
	RequiresMFA(ctx context.Context, userID string, extra map[string]any) (bool, error)

	// CreateMFAChallenge generates a secure, short-lived anti-tampering challenge for the user.
	CreateMFAChallenge(ctx context.Context, userID string, factor string) (*dto.AuthChallenge, error)

	// VerifyMFAChallenge validates the challenge token and submitted code, atomically revoking the challenge on success.
	VerifyMFAChallenge(ctx context.Context, params dto.VerifyChallengeParams) (*dto.ChallengeVerificationResult, error)
}
