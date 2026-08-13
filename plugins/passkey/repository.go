package passkey

import (
	"context"
	"errors"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

// Sentinel errors for the Passkey plugin.
var (
	ErrPasskeyNotFound       = errors.New("passkey: passkey not found")
	ErrPasskeyAlreadyExists   = errors.New("passkey: passkey credential already registered")
	ErrChallengeNotFound      = errors.New("passkey: challenge not found or expired")
	ErrChallengeExpired       = errors.New("passkey: challenge has expired")
	ErrInvalidCeremonyType    = errors.New("passkey: invalid ceremony type for this challenge")
	ErrUnauthorized           = errors.New("passkey: unauthorized to perform this operation")
	ErrVerificationFailed     = errors.New("passkey: failed to verify webauthn ceremony response")
	ErrCounterNotIncremented  = errors.New("passkey: signature counter did not increment (possible authenticator clone)")
	ErrUserNotFound           = errors.New("passkey: user not found")
	ErrSessionRequired        = errors.New("passkey: passkey registration requires an authenticated session")
	ErrResolveUserRequired    = errors.New("passkey: resolveUser callback is required when requireSession is false and no session exists")
	ErrInvalidResolvedUser    = errors.New("passkey: resolved user is invalid")
	ErrOriginMissing          = errors.New("passkey: origin is missing in request context")
	ErrInvalidParameter       = errors.New("passkey: invalid parameter provided")
	ErrUnableToCreateSession  = errors.New("passkey: unable to create user session")
	ErrFailedToUpdatePasskey  = errors.New("passkey: failed to update passkey")
)

// CeremonyType defines the type of WebAuthn ceremony.
type CeremonyType string

const (
	CeremonyRegistration   CeremonyType = "registration"
	CeremonyAuthentication CeremonyType = "authentication"
)

// PasskeyChallenge represents the ephemeral state of an in-flight WebAuthn challenge.
type PasskeyChallenge struct {
	Token       string       `json:"token"`
	Type        CeremonyType `json:"type"`
	Challenge   string       `json:"challenge"`
	UserID      *string      `json:"userId,omitempty"`
	UserName    *string      `json:"userName,omitempty"`
	DisplayName *string      `json:"displayName,omitempty"`
	Context     *string      `json:"context,omitempty"`
	SessionData string       `json:"sessionData"` // Serialized JSON of webauthn.SessionData
	ExpiresAt   time.Time    `json:"expiresAt"`
	CreatedAt   time.Time    `json:"createdAt"`
}

// Repository defines the storage contract required by the Passkey authentication plugin.
type Repository interface {
	// Passkeys CRUD
	CreatePasskey(ctx context.Context, passkey *entity.Passkey) error
	GetPasskeyByID(ctx context.Context, id string) (*entity.Passkey, error)
	GetPasskeyByCredentialID(ctx context.Context, credentialID string) (*entity.Passkey, error)
	ListPasskeysByUserID(ctx context.Context, userID string) ([]*entity.Passkey, error)
	UpdatePasskey(ctx context.Context, passkey *entity.Passkey) error
	UpdatePasskeyCounter(ctx context.Context, id string, newCounter uint32) error
	DeletePasskey(ctx context.Context, id string) error
	DeletePasskeysByUserID(ctx context.Context, userID string) error

	// Ephemeral Challenges
	SavePasskeyChallenge(ctx context.Context, challenge *PasskeyChallenge) error
	GetPasskeyChallenge(ctx context.Context, token string) (*PasskeyChallenge, error)
	ConsumePasskeyChallenge(ctx context.Context, token string) (*PasskeyChallenge, error)
	DeletePasskeyChallenge(ctx context.Context, token string) error

	// User & Session Integration
	GetUserByID(ctx context.Context, userID string) (*entity.User, error)
	GetUserByEmail(ctx context.Context, email string) (*entity.User, error)
	CreateSession(ctx context.Context, session *dto.CreateSessionParams) (*entity.Session, error)
}
