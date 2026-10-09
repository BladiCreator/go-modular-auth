package memory

import (
	"context"
	"sync"

	"github.com/BladiCreator/go-modular-auth-lastlogin/store"
)

type Store struct {
	mu      sync.RWMutex
	records map[string]*store.Record
}

var _ store.Store = (*Store)(nil)

func New() *Store {
	return &Store{
		records: make(map[string]*store.Record),
	}
}

func (s *Store) Save(ctx context.Context, record *store.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cp := *record
	s.records[record.UserID] = &cp
	return nil
}

func (s *Store) GetByUserID(ctx context.Context, userID string) (*store.Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rec, ok := s.records[userID]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *rec
	return &cp, nil
}
