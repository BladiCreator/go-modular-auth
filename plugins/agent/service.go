package agent

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/BladiCreator/go-modular-auth/adapter"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
)

type AgentManager interface {
	CreateAgent(ctx context.Context, ownerID, name, description string, scopes []string, metadata map[string]string) (*Agent, error)
	GetAgent(ctx context.Context, id string) (*Agent, error)
	ListAgents(ctx context.Context, ownerID string) ([]*Agent, error)
	UpdateAgent(ctx context.Context, a *Agent) error
	DeleteAgent(ctx context.Context, id string) error

	IssueCredential(ctx context.Context, agentID string, ttl time.Duration) (string, *Credential, error)
	ValidateCredential(ctx context.Context, token string) (*Agent, *Credential, error)
	RevokeCredential(ctx context.Context, credentialID string) error
}

type service struct {
	ctx    *sdk.Context
	agents *sdk.Repository[Agent]
	creds  *sdk.Repository[Credential]
}

var _ AgentManager = (*service)(nil)

func newService(ctx *sdk.Context) *service {
	return &service{
		ctx:    ctx,
		agents: sdk.Model[Agent](ctx, ModelAgents),
		creds:  sdk.Model[Credential](ctx, ModelAgentCredentials),
	}
}

func generateID(prefix string) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func (s *service) now() time.Time {
	if s.ctx != nil {
		return s.ctx.Now()
	}
	return time.Now()
}

func (s *service) CreateAgent(ctx context.Context, ownerID, name, description string, scopes []string, metadata map[string]string) (*Agent, error) {
	if ownerID == "" {
		return nil, ErrInvalidOwnerID
	}
	if name == "" {
		return nil, ErrInvalidName
	}

	now := s.now()
	id := generateID("agt")

	ag := &Agent{
		ID:          id,
		Name:        name,
		Description: description,
		OwnerID:     ownerID,
		Scopes:      scopes,
		Metadata:    metadata,
		Active:      true,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := s.agents.Create(ctx, ag); err != nil {
		return nil, err
	}

	return ag, nil
}

func (s *service) GetAgent(ctx context.Context, id string) (*Agent, error) {
	if id == "" {
		return nil, ErrNotFound
	}
	ag, err := s.agents.FindOne(ctx, adapter.Eq("id", id))
	if errors.Is(err, adapter.ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return ag, nil
}

func (s *service) ListAgents(ctx context.Context, ownerID string) ([]*Agent, error) {
	if ownerID == "" {
		return nil, ErrInvalidOwnerID
	}
	records, err := s.agents.FindMany(ctx, adapter.Query{
		Model: ModelAgents,
		Where: []adapter.Condition{adapter.Eq("owner_id", ownerID)},
	})
	if err != nil {
		return nil, err
	}

	res := make([]*Agent, len(records))
	for i := range records {
		res[i] = &records[i]
	}
	return res, nil
}

func (s *service) UpdateAgent(ctx context.Context, a *Agent) error {
	if a == nil || a.ID == "" {
		return ErrNotFound
	}
	a.UpdatedAt = s.now()
	affected, err := s.agents.Update(ctx, []adapter.Condition{adapter.Eq("id", a.ID)}, map[string]any{
		"name":        a.Name,
		"description": a.Description,
		"owner_id":    a.OwnerID,
		"scopes":      a.Scopes,
		"metadata":    a.Metadata,
		"active":      a.Active,
		"updated_at":  a.UpdatedAt,
	})
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *service) DeleteAgent(ctx context.Context, id string) error {
	if id == "" {
		return ErrNotFound
	}
	affected, err := s.agents.Delete(ctx, adapter.Eq("id", id))
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *service) IssueCredential(ctx context.Context, agentID string, ttl time.Duration) (string, *Credential, error) {
	if agentID == "" {
		return "", nil, ErrNotFound
	}
	if ttl <= 0 {
		return "", nil, ErrInvalidTTL
	}

	ag, err := s.GetAgent(ctx, agentID)
	if err != nil {
		return "", nil, err
	}
	if !ag.Active {
		return "", nil, ErrAgentInactive
	}

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", nil, err
	}
	plainToken := "mcp_" + hex.EncodeToString(tokenBytes)
	hashed := hashToken(plainToken)

	now := s.now()
	credID := generateID("cred")
	expiresAt := now.Add(ttl)

	cred := &Credential{
		ID:        credID,
		AgentID:   agentID,
		TokenHash: hashed,
		ExpiresAt: expiresAt,
		CreatedAt: now,
	}

	if err := s.creds.Create(ctx, cred); err != nil {
		return "", nil, err
	}

	return plainToken, cred, nil
}

func (s *service) ValidateCredential(ctx context.Context, token string) (*Agent, *Credential, error) {
	if token == "" {
		return nil, nil, ErrInvalidToken
	}

	hashed := hashToken(token)
	cred, err := s.creds.FindOne(ctx, adapter.Eq("token_hash", hashed))
	if errors.Is(err, adapter.ErrNotFound) {
		return nil, nil, ErrInvalidToken
	}
	if err != nil {
		return nil, nil, err
	}

	now := s.now()
	if now.After(cred.ExpiresAt) {
		_, _ = s.creds.Delete(ctx, adapter.Eq("id", cred.ID))
		return nil, nil, ErrInvalidToken
	}

	ag, err := s.GetAgent(ctx, cred.AgentID)
	if err != nil {
		return nil, nil, err
	}
	if !ag.Active {
		return nil, nil, ErrAgentInactive
	}

	return ag, cred, nil
}

func (s *service) RevokeCredential(ctx context.Context, credentialID string) error {
	if credentialID == "" {
		return ErrNotFound
	}
	affected, err := s.creds.Delete(ctx, adapter.Eq("id", credentialID))
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}
