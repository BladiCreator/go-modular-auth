package memory

import (
	"context"
	"errors"
	"sync"

	"github.com/BladiCreator/go-modular-auth-policy/store"
)

var (
	ErrNotFound = errors.New("policy record not found")
)

type MemoryStore struct {
	mu      sync.RWMutex
	records map[string]*store.PolicyRecord
}

var _ store.Store = (*MemoryStore)(nil)

func NewStore() *MemoryStore {
	return &MemoryStore{
		records: make(map[string]*store.PolicyRecord),
	}
}

func (s *MemoryStore) SavePolicyRecord(_ context.Context, r *store.PolicyRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cp := *r
	s.records[r.ID] = &cp
	return nil
}

func (s *MemoryStore) GetPolicyRecord(_ context.Context, id string) (*store.PolicyRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	r, exists := s.records[id]
	if !exists {
		return nil, ErrNotFound
	}
	cp := *r
	return &cp, nil
}

func (s *MemoryStore) ListPolicyRecords(_ context.Context) ([]*store.PolicyRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	res := make([]*store.PolicyRecord, 0, len(s.records))
	for _, r := range s.records {
		cp := *r
		res = append(res, &cp)
	}
	return res, nil
}

func (s *MemoryStore) DeletePolicyRecord(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.records, id)
	return nil
}
