// Package memory provides an in-memory implementation of store.Store,
// suitable for testing, local development, and ephemeral environments.
package memory

import (
	"context"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/BladiCreator/go-modular-auth-bearer/store"
)

// Store implements an in-memory, thread-safe bearer token store.
type Store struct {
	mu     sync.RWMutex
	byID   map[string]*store.TokenRecord
	byHash map[string]string // hash -> ID
}

var _ store.Store = (*Store)(nil)

// New constructs an initialized in-memory store.
func New() *Store {
	return &Store{
		byID:   make(map[string]*store.TokenRecord),
		byHash: make(map[string]string),
	}
}

// Create persists a new token record.
func (s *Store) Create(_ context.Context, record *store.TokenRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.byID[record.ID]; exists {
		return store.ErrConflict
	}
	if _, exists := s.byHash[record.TokenHash]; exists {
		return store.ErrConflict
	}

	clone := cloneRecord(record)
	s.byID[record.ID] = clone
	s.byHash[record.TokenHash] = record.ID
	return nil
}

// GetByID retrieves a token record by its ID.
func (s *Store) GetByID(_ context.Context, id string) (*store.TokenRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rec, exists := s.byID[id]
	if !exists {
		return nil, store.ErrNotFound
	}
	return cloneRecord(rec), nil
}

// GetByTokenHash retrieves a token record by its token hash.
func (s *Store) GetByTokenHash(_ context.Context, tokenHash string) (*store.TokenRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	id, exists := s.byHash[tokenHash]
	if !exists {
		return nil, store.ErrNotFound
	}
	rec, exists := s.byID[id]
	if !exists {
		return nil, store.ErrNotFound
	}
	return cloneRecord(rec), nil
}

// Update updates an existing token record.
func (s *Store) Update(_ context.Context, record *store.TokenRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, exists := s.byID[record.ID]
	if !exists {
		return store.ErrNotFound
	}

	// If token hash changed, update hash index
	if existing.TokenHash != record.TokenHash {
		if _, exists := s.byHash[record.TokenHash]; exists {
			return store.ErrConflict
		}
		delete(s.byHash, existing.TokenHash)
		s.byHash[record.TokenHash] = record.ID
	}

	s.byID[record.ID] = cloneRecord(record)
	return nil
}

// Revoke sets the RevokedAt timestamp for a single token.
func (s *Store) Revoke(_ context.Context, id string, revokedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, exists := s.byID[id]
	if !exists {
		return store.ErrNotFound
	}

	if existing.RevokedAt == nil {
		t := revokedAt
		existing.RevokedAt = &t
		existing.UpdatedAt = revokedAt
	}
	return nil
}

// RevokeBySubject sets the RevokedAt timestamp for all active tokens belonging to subject.
func (s *Store) RevokeBySubject(_ context.Context, subject string, revokedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, rec := range s.byID {
		if rec.Subject == subject && rec.RevokedAt == nil {
			t := revokedAt
			rec.RevokedAt = &t
			rec.UpdatedAt = revokedAt
		}
	}
	return nil
}

// Delete permanently removes a token record by its ID.
func (s *Store) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, exists := s.byID[id]
	if !exists {
		return store.ErrNotFound
	}

	delete(s.byHash, existing.TokenHash)
	delete(s.byID, id)
	return nil
}

// DeleteExpired permanently deletes tokens that expired before the given timestamp or were revoked before it.
func (s *Store) DeleteExpired(_ context.Context, before time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	count := 0
	for id, rec := range s.byID {
		isExpired := !rec.ExpiresAt.IsZero() && !before.Before(rec.ExpiresAt)
		isRevoked := rec.RevokedAt != nil && !before.Before(*rec.RevokedAt)
		if isExpired || isRevoked {
			delete(s.byHash, rec.TokenHash)
			delete(s.byID, id)
			count++
		}
	}
	return count, nil
}

// ListBySubject retrieves all token records for a given subject.
func (s *Store) ListBySubject(_ context.Context, subject string) ([]*store.TokenRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*store.TokenRecord
	for _, rec := range s.byID {
		if rec.Subject == subject {
			result = append(result, cloneRecord(rec))
		}
	}
	return result, nil
}

func cloneRecord(r *store.TokenRecord) *store.TokenRecord {
	if r == nil {
		return nil
	}
	c := *r
	if r.Scopes != nil {
		c.Scopes = slices.Clone(r.Scopes)
	}
	if r.Metadata != nil {
		c.Metadata = maps.Clone(r.Metadata)
	}
	if r.RevokedAt != nil {
		t := *r.RevokedAt
		c.RevokedAt = &t
	}
	return &c
}
