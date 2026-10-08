// Package memory provides an in-memory implementation of store.Store for the anonymous plugin.
package memory

import (
	"context"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/BladiCreator/go-modular-auth-anonymous/store"
)

// Store implements store.Store entirely in memory.
// It is safe for concurrent use and ideal for testing and development.
type Store struct {
	mu       sync.RWMutex
	byID     map[string]*store.Identity
	byUserID map[string]*store.Identity
}

var _ store.Store = (*Store)(nil)

// New returns a new empty in-memory anonymous identity store.
func New() *Store {
	return &Store{
		byID:     make(map[string]*store.Identity),
		byUserID: make(map[string]*store.Identity),
	}
}

// Create persists a new anonymous identity.
func (s *Store) Create(ctx context.Context, id *store.Identity) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.byID[id.ID]; exists {
		return store.ErrConflict
	}
	if _, exists := s.byUserID[id.UserID]; exists {
		return store.ErrConflict
	}

	clone := cloneIdentity(id)
	s.byID[id.ID] = clone
	s.byUserID[id.UserID] = clone
	return nil
}

// GetByID retrieves an anonymous identity by its identity ID.
func (s *Store) GetByID(ctx context.Context, id string) (*store.Identity, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	found, ok := s.byID[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneIdentity(found), nil
}

// GetByUserID retrieves an anonymous identity by its Core User ID.
func (s *Store) GetByUserID(ctx context.Context, userID string) (*store.Identity, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	found, ok := s.byUserID[userID]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneIdentity(found), nil
}

// Update updates an existing anonymous identity record.
func (s *Store) Update(ctx context.Context, id *store.Identity) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, ok := s.byID[id.ID]
	if !ok {
		return store.ErrNotFound
	}

	// If UserID changed, verify uniqueness
	if existing.UserID != id.UserID {
		if other, taken := s.byUserID[id.UserID]; taken && other.ID != id.ID {
			return store.ErrConflict
		}
		delete(s.byUserID, existing.UserID)
	}

	clone := cloneIdentity(id)
	s.byID[id.ID] = clone
	s.byUserID[id.UserID] = clone
	return nil
}

// Delete removes an anonymous identity by its identity ID.
func (s *Store) Delete(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, ok := s.byID[id]
	if !ok {
		return store.ErrNotFound
	}

	delete(s.byUserID, existing.UserID)
	delete(s.byID, id)
	return nil
}

// ListExpired returns unconverted anonymous identities expired before the given instant.
func (s *Store) ListExpired(ctx context.Context, before time.Time, limit int) ([]*store.Identity, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	var expired []*store.Identity
	for _, id := range s.byID {
		if !id.Converted() && id.Expired(before) {
			expired = append(expired, cloneIdentity(id))
		}
	}

	// Sort chronologically by ExpiresAt for predictable batching
	slices.SortFunc(expired, func(a, b *store.Identity) int {
		if a.ExpiresAt.Before(b.ExpiresAt) {
			return -1
		}
		if a.ExpiresAt.After(b.ExpiresAt) {
			return 1
		}
		return 0
	})

	if limit > 0 && len(expired) > limit {
		expired = expired[:limit]
	}

	return expired, nil
}

func cloneIdentity(in *store.Identity) *store.Identity {
	if in == nil {
		return nil
	}
	c := *in
	if in.ConvertedAt != nil {
		conv := *in.ConvertedAt
		c.ConvertedAt = &conv
	}
	if in.Metadata != nil {
		c.Metadata = maps.Clone(in.Metadata)
	}
	return &c
}
