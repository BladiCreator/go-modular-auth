package agent

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
	"github.com/BladiCreator/go-modular-auth-agent/store"
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
	ctx   *sdk.Context
	store store.Store
}

var _ AgentManager = (*service)(nil)

func newService(ctx *sdk.Context, st store.Store) *service {
	return &service{
		ctx:   ctx,
		store: st,
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

func (s *service) CreateAgent(ctx context.Context, ownerID, name, description string, scopes []string, metadata map[string]string) (*Agent, error) {
	if ownerID == "" {
		return nil, ErrInvalidOwnerID
	}
	if name == "" {
		return nil, ErrInvalidName
	}

	now := s.ctx.Now()
	id := generateID("agt")

	rec := &store.AgentRecord{
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

	if err := s.store.CreateAgent(ctx, rec); err != nil {
		return nil, err
	}

	return &Agent{
		ID:          rec.ID,
		Name:        rec.Name,
		Description: rec.Description,
		OwnerID:     rec.OwnerID,
		Scopes:      rec.Scopes,
		Metadata:    rec.Metadata,
		Active:      rec.Active,
		CreatedAt:   rec.CreatedAt,
		UpdatedAt:   rec.UpdatedAt,
	}, nil
}

func (s *service) GetAgent(ctx context.Context, id string) (*Agent, error) {
	if id == "" {
		return nil, ErrNotFound
	}
	rec, err := s.store.GetAgent(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	return &Agent{
		ID:          rec.ID,
		Name:        rec.Name,
		Description: rec.Description,
		OwnerID:     rec.OwnerID,
		Scopes:      rec.Scopes,
		Metadata:    rec.Metadata,
		Active:      rec.Active,
		CreatedAt:   rec.CreatedAt,
		UpdatedAt:   rec.UpdatedAt,
	}, nil
}

func (s *service) ListAgents(ctx context.Context, ownerID string) ([]*Agent, error) {
	if ownerID == "" {
		return nil, ErrInvalidOwnerID
	}
	records, err := s.store.ListAgentsByOwner(ctx, ownerID)
	if err != nil {
		return nil, err
	}

	res := make([]*Agent, len(records))
	for i, r := range records {
		res[i] = &Agent{
			ID:          r.ID,
			Name:        r.Name,
			Description: r.Description,
			OwnerID:     r.OwnerID,
			Scopes:      r.Scopes,
			Metadata:    r.Metadata,
			Active:      r.Active,
			CreatedAt:   r.CreatedAt,
			UpdatedAt:   r.UpdatedAt,
		}
	}
	return res, nil
}

func (s *service) UpdateAgent(ctx context.Context, a *Agent) error {
	if a == nil || a.ID == "" {
		return ErrNotFound
	}
	a.UpdatedAt = s.ctx.Now()
	rec := &store.AgentRecord{
		ID:          a.ID,
		Name:        a.Name,
		Description: a.Description,
		OwnerID:     a.OwnerID,
		Scopes:      a.Scopes,
		Metadata:    a.Metadata,
		Active:      a.Active,
		CreatedAt:   a.CreatedAt,
		UpdatedAt:   a.UpdatedAt,
	}
	return s.store.UpdateAgent(ctx, rec)
}

func (s *service) DeleteAgent(ctx context.Context, id string) error {
	if id == "" {
		return ErrNotFound
	}
	return s.store.DeleteAgent(ctx, id)
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

	now := s.ctx.Now()
	credID := generateID("cred")
	expiresAt := now.Add(ttl)

	cRec := &store.CredentialRecord{
		ID:        credID,
		AgentID:   agentID,
		TokenHash: hashed,
		ExpiresAt: expiresAt,
		CreatedAt: now,
	}

	if err := s.store.SaveCredential(ctx, cRec); err != nil {
		return "", nil, err
	}

	cred := &Credential{
		ID:        cRec.ID,
		AgentID:   cRec.AgentID,
		TokenHash: cRec.TokenHash,
		ExpiresAt: cRec.ExpiresAt,
		CreatedAt: cRec.CreatedAt,
	}

	return plainToken, cred, nil
}

func (s *service) ValidateCredential(ctx context.Context, token string) (*Agent, *Credential, error) {
	if token == "" {
		return nil, nil, ErrInvalidToken
	}

	hashed := hashToken(token)
	cRec, err := s.store.GetCredentialByHash(ctx, hashed)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil, ErrInvalidToken
	}
	if err != nil {
		return nil, nil, err
	}

	now := s.ctx.Now()
	if now.After(cRec.ExpiresAt) {
		_ = s.store.RevokeCredential(ctx, cRec.ID)
		return nil, nil, ErrInvalidToken
	}

	ag, err := s.GetAgent(ctx, cRec.AgentID)
	if err != nil {
		return nil, nil, err
	}
	if !ag.Active {
		return nil, nil, ErrAgentInactive
	}

	cred := &Credential{
		ID:        cRec.ID,
		AgentID:   cRec.AgentID,
		TokenHash: cRec.TokenHash,
		ExpiresAt: cRec.ExpiresAt,
		CreatedAt: cRec.CreatedAt,
	}

	return ag, cred, nil
}

func (s *service) RevokeCredential(ctx context.Context, credentialID string) error {
	if credentialID == "" {
		return ErrNotFound
	}
	return s.store.RevokeCredential(ctx, credentialID)
}
