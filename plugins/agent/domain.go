package agent

import (
	"errors"
	"time"
)

var (
	ErrNotFound          = errors.New("agent: not found")
	ErrAgentInactive     = errors.New("agent: agent is inactive")
	ErrInvalidToken      = errors.New("agent: token is invalid or expired")
	ErrInvalidOwnerID    = errors.New("agent: owner_id is required")
	ErrInvalidName       = errors.New("agent: name is required")
	ErrInvalidTTL        = errors.New("agent: credential ttl must be positive")
)

// Agent represents an autonomous AI agent or MCP client identity.
type Agent struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	OwnerID     string            `json:"owner_id"`
	Scopes      []string          `json:"scopes"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Active      bool              `json:"active"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// Credential represents a short-lived token issued to an agent.
type Credential struct {
	ID        string    `json:"id"`
	AgentID   string    `json:"agent_id"`
	TokenHash string    `json:"token_hash"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}
