package dto

import (
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

const (
	// AuthStatusComplete indicates that authentication succeeded and an active session was issued.
	AuthStatusComplete = "complete"

	// AuthStatusMFARequired indicates that secondary authentication (MFA / 2FA challenge) is required.
	AuthStatusMFARequired = "mfa_required"
)

type (
	// AuthChallenge represents an ephemeral multi-factor authentication challenge issued to a user.
	AuthChallenge struct {
		ChallengeID    string    `json:"challenge_id"`
		UserID         string    `json:"user_id"`
		FactorRequired string    `json:"factor_required"` // "totp", "otp", "backup_code"
		TempToken      string    `json:"temp_token"`
		ExpiresAt      time.Time `json:"expires_at"`
		CreatedAt      time.Time `json:"created_at"`
	}

	// VerifyChallengeParams defines parameters submitted by the client to solve an active MFA challenge.
	VerifyChallengeParams struct {
		ChallengeToken string `json:"challenge_token" binding:"required"`
		Code           string `json:"code" binding:"required"`
		Method         string `json:"method,omitzero"` // "totp", "backup_code", "otp" (optional, auto-fallback)
		TrustDevice    bool   `json:"trust_device,omitzero"`
		DeviceID       string `json:"device_id,omitzero"`
	}

	// ChallengeVerificationResult contains data produced upon successfully validating an MFA challenge.
	ChallengeVerificationResult struct {
		UserID           string `json:"user_id"`
		Method           string `json:"method"`
		TrustDeviceToken string `json:"trust_device_token,omitzero"`
		RemainingCodes   int    `json:"remaining_codes,omitzero"`
	}

	// AuthResult represents the polymorphic response of a sign-in operation.
	// It holds either an active SessionData (when authentication is complete)
	// or an AuthChallenge (when multi-factor authentication is required).
	AuthResult struct {
		Status          string          `json:"status"` // "complete" | "mfa_required"
		Session         *entity.Session `json:"session,omitzero"`
		User            *entity.User    `json:"user,omitzero"`
		ChallengeDetail *AuthChallenge  `json:"challenge,omitzero"`

		sessionData *SessionData
		challenge   *AuthChallenge
	}
)

// NewAuthResultCompleted creates an AuthResult representing a fully completed authentication session.
func NewAuthResultCompleted(data *SessionData) *AuthResult {
	if data == nil {
		return &AuthResult{Status: AuthStatusComplete}
	}
	return &AuthResult{
		Status:      AuthStatusComplete,
		Session:     data.Session,
		User:        data.User,
		sessionData: data,
	}
}

// NewAuthResultChallenge creates an AuthResult indicating that an MFA challenge must be resolved.
func NewAuthResultChallenge(challenge *AuthChallenge) *AuthResult {
	if challenge == nil {
		return &AuthResult{Status: AuthStatusMFARequired}
	}
	return &AuthResult{
		Status:          AuthStatusMFARequired,
		ChallengeDetail: challenge,
		challenge:       challenge,
	}
}

// IsComplete returns true if the authentication operation completed and an active session is available.
func (r *AuthResult) IsComplete() bool {
	return r != nil && r.Status == AuthStatusComplete && r.sessionData != nil && r.Session != nil
}

// RequiresChallenge returns true if the authentication operation requires an MFA second factor.
func (r *AuthResult) RequiresChallenge() bool {
	return r != nil && r.Status == AuthStatusMFARequired && (r.challenge != nil || r.ChallengeDetail != nil)
}

// SessionData returns the completed *SessionData, or nil if a challenge is pending or result is uninitialized.
func (r *AuthResult) SessionData() *SessionData {
	if r == nil {
		return nil
	}
	if r.sessionData != nil {
		return r.sessionData
	}
	if r.Session != nil || r.User != nil {
		return &SessionData{
			Session: r.Session,
			User:    r.User,
		}
	}
	return nil
}

// Challenge returns the pending *AuthChallenge, or nil if authentication is complete.
func (r *AuthResult) Challenge() *AuthChallenge {
	if r == nil {
		return nil
	}
	if r.challenge != nil {
		return r.challenge
	}
	return r.ChallengeDetail
}

// ChallengeData is an alias for Challenge().
func (r *AuthResult) ChallengeData() *AuthChallenge {
	return r.Challenge()
}
