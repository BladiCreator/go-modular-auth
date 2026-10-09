package memory

import (
	"context"
	"sync"

	"github.com/BladiCreator/go-modular-auth-service-accounts/store"
)

type Store struct {
	mu       sync.RWMutex
	accounts map[string]*store.Record
}

var _ store.Store = (*Store)(nil)

func New() *Store {
	return &Store{
		accounts: make(map[string]*store.Record),
	}
}

func (s *Store) Create(ctx context.Context, sa *store.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.accounts[sa.ID]; exists {
		return store.ErrConflict
	}
	cp := *sa
	s.accounts[sa.ID] = &cp
	return nil
}

func (s *Store) GetByID(ctx context.Context, id string) (*store.Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sa, ok := s.accounts[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *sa
	return &cp, nil
}

func (s *Store) List(ctx context.Context, ownerID string) ([]*store.Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var res []*store.Record
	for _, sa := range s.accounts {
		if ownerID == "" || sa.OwnerID == ownerID {
			cp := *sa
			res = append(res, &cp)
		}
	}
	return res, nil
}

func (s *Store) Update(ctx context.Context, sa *store.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.accounts[sa.ID]; !exists {
		return store.ErrNotFound
	}
	cp := *sa
	s.accounts[sa.ID] = &cp
	return nil
}

func (s *Store) Delete(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.accounts[id]; !exists {
		return store.ErrNotFound
	}
	delete(s.accounts, id)
	return nil
}
