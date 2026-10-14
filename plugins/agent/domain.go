package agent

import (
	"errors"
	"time"

	"github.com/BladiCreator/go-modular-auth/schema"
)

var (
	ErrNotFound       = errors.New("agent: not found")
	ErrAgentInactive  = errors.New("agent: agent is inactive")
	ErrInvalidToken   = errors.New("agent: token is invalid or expired")
	ErrInvalidOwnerID = errors.New("agent: owner_id is required")
	ErrInvalidName    = errors.New("agent: name is required")
	ErrInvalidTTL     = errors.New("agent: credential ttl must be positive")
)

const (
	ModelAgents           = "agents"
	ModelAgentCredentials = "agent_credentials"
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

// RegisterSchema registers agent and credential models into the unified schema.
func RegisterSchema(s *schema.Schema) error {
	agentModel := schema.NewModel(ModelAgents, ModelAgents, "id")
	_ = agentModel.AddField(schema.Field{Name: "id", Type: schema.TypeString, Required: true})
	_ = agentModel.AddField(schema.Field{Name: "name", Type: schema.TypeString, Required: true})
	_ = agentModel.AddField(schema.Field{Name: "description", Type: schema.TypeString})
	_ = agentModel.AddField(schema.Field{Name: "owner_id", Type: schema.TypeString, Required: true})
	_ = agentModel.AddField(schema.Field{Name: "scopes", Type: schema.TypeJSON})
	_ = agentModel.AddField(schema.Field{Name: "metadata", Type: schema.TypeJSON})
	_ = agentModel.AddField(schema.Field{Name: "active", Type: schema.TypeBool, Required: true})
	_ = agentModel.AddField(schema.Field{Name: "created_at", Type: schema.TypeTime, Required: true})
	_ = agentModel.AddField(schema.Field{Name: "updated_at", Type: schema.TypeTime, Required: true})
	agentModel.Indexes = []schema.Index{
		{Name: "idx_agents_owner_id", Fields: []string{"owner_id"}},
	}
	if err := s.AddModel(agentModel); err != nil {
		return err
	}

	credModel := schema.NewModel(ModelAgentCredentials, ModelAgentCredentials, "id")
	_ = credModel.AddField(schema.Field{Name: "id", Type: schema.TypeString, Required: true})
	_ = credModel.AddField(schema.Field{Name: "agent_id", Type: schema.TypeString, Required: true})
	_ = credModel.AddField(schema.Field{Name: "token_hash", Type: schema.TypeString, Required: true, Unique: true})
	_ = credModel.AddField(schema.Field{Name: "expires_at", Type: schema.TypeTime, Required: true})
	_ = credModel.AddField(schema.Field{Name: "created_at", Type: schema.TypeTime, Required: true})
	credModel.Indexes = []schema.Index{
		{Name: "idx_agent_credentials_token_hash", Fields: []string{"token_hash"}, Unique: true},
		{Name: "idx_agent_credentials_agent_id", Fields: []string{"agent_id"}},
	}
	return s.AddModel(credModel)
}
