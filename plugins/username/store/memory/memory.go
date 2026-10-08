package memory

import (
	"context"
	"sync"

	"github.com/BladiCreator/go-modular-auth-username/store"
)

// Store provides an in-memory implementation of store.Store.
// It is thread-safe and suitable for unit tests and local development.
type Store struct {
	mu           sync.RWMutex
	byUserID     map[string]*store.Record
	byNormalized map[string]*store.Record
}

// New returns a new empty in-memory Store.
func New() *Store {
	return &Store{
		byUserID:     make(map[string]*store.Record),
		byNormalized: make(map[string]*store.Record),
	}
}

func (s *Store) Create(ctx context.Context, rec *store.Record) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.byUserID[rec.UserID]; exists {
		return store.ErrConflict
	}
	if _, exists := s.byNormalized[rec.Normalized]; exists {
		return store.ErrConflict
	}

	clone := *rec
	s.byUserID[rec.UserID] = &clone
	s.byNormalized[rec.Normalized] = &clone
	return nil
}

func (s *Store) GetByNormalized(ctx context.Context, normalized string) (*store.Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	rec, ok := s.byNormalized[normalized]
	if !ok {
		return nil, store.ErrNotFound
	}
	clone := *rec
	return &clone, nil
}

func (s *Store) GetByUserID(ctx context.Context, userID string) (*store.Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	rec, ok := s.byUserID[userID]
	if !ok {
		return nil, store.ErrNotFound
	}
	clone := *rec
	return &clone, nil
}

func (s *Store) Update(ctx context.Context, rec *store.Record) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, ok := s.byUserID[rec.UserID]
	if !ok {
		return store.ErrNotFound
	}

	// If normalized changed, check if new normalized is already claimed by someone else
	if existing.Normalized != rec.Normalized {
		if other, taken := s.byNormalized[rec.Normalized]; taken && other.UserID != rec.UserID {
			return store.ErrConflict
		}
		delete(s.byNormalized, existing.Normalized)
	}

	clone := *rec
	s.byUserID[rec.UserID] = &clone
	s.byNormalized[rec.Normalized] = &clone
	return nil
}

func (s *Store) Delete(ctx context.Context, userID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.byUserID[userID]
	if !ok {
		return store.ErrNotFound
	}

	delete(s.byNormalized, rec.Normalized)
	delete(s.byUserID, userID)
	return nil
}
