package store

import (
	"context"
	"errors"
	"time"
)

var (
	ErrNotFound = errors.New("agent/store: not found")
	ErrConflict = errors.New("agent/store: conflict")
)

type AgentRecord struct {
	ID          string
	Name        string
	Description string
	OwnerID     string
	Scopes      []string
	Metadata    map[string]string
	Active      bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type CredentialRecord struct {
	ID        string
	AgentID   string
	TokenHash string
	ExpiresAt time.Time
	CreatedAt time.Time
}

type Store interface {
	CreateAgent(ctx context.Context, a *AgentRecord) error
	GetAgent(ctx context.Context, id string) (*AgentRecord, error)
	ListAgentsByOwner(ctx context.Context, ownerID string) ([]*AgentRecord, error)
	UpdateAgent(ctx context.Context, a *AgentRecord) error
	DeleteAgent(ctx context.Context, id string) error

	SaveCredential(ctx context.Context, c *CredentialRecord) error
	GetCredentialByHash(ctx context.Context, hash string) (*CredentialRecord, error)
	RevokeCredential(ctx context.Context, id string) error
	DeleteExpiredCredentials(ctx context.Context, before time.Time) error
}
