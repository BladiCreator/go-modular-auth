package memory

import (
	"context"
	"sync"
	"time"

	"github.com/BladiCreator/go-modular-auth-agent/store"
)

type Store struct {
	mu          sync.RWMutex
	agents      map[string]*store.AgentRecord
	credentials map[string]*store.CredentialRecord // keyed by tokenHash
}

var _ store.Store = (*Store)(nil)

func New() *Store {
	return &Store{
		agents:      make(map[string]*store.AgentRecord),
		credentials: make(map[string]*store.CredentialRecord),
	}
}

func (s *Store) CreateAgent(ctx context.Context, a *store.AgentRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.agents[a.ID]; exists {
		return store.ErrConflict
	}
	cp := *a
	s.agents[a.ID] = &cp
	return nil
}

func (s *Store) GetAgent(ctx context.Context, id string) (*store.AgentRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	a, ok := s.agents[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *a
	return &cp, nil
}

func (s *Store) ListAgentsByOwner(ctx context.Context, ownerID string) ([]*store.AgentRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var list []*store.AgentRecord
	for _, a := range s.agents {
		if a.OwnerID == ownerID {
			cp := *a
			list = append(list, &cp)
		}
	}
	return list, nil
}

func (s *Store) UpdateAgent(ctx context.Context, a *store.AgentRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.agents[a.ID]; !exists {
		return store.ErrNotFound
	}
	cp := *a
	s.agents[a.ID] = &cp
	return nil
}

func (s *Store) DeleteAgent(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.agents[id]; !exists {
		return store.ErrNotFound
	}
	delete(s.agents, id)
	return nil
}

func (s *Store) SaveCredential(ctx context.Context, c *store.CredentialRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cp := *c
	s.credentials[c.TokenHash] = &cp
	return nil
}

func (s *Store) GetCredentialByHash(ctx context.Context, hash string) (*store.CredentialRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	c, ok := s.credentials[hash]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *c
	return &cp, nil
}

func (s *Store) RevokeCredential(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for h, c := range s.credentials {
		if c.ID == id {
			delete(s.credentials, h)
			return nil
		}
	}
	return store.ErrNotFound
}

func (s *Store) DeleteExpiredCredentials(ctx context.Context, before time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for h, c := range s.credentials {
		if c.ExpiresAt.Before(before) {
			delete(s.credentials, h)
		}
	}
	return nil
}
