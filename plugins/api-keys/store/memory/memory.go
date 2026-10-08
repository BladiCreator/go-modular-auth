// Package memory implements an in-memory thread-safe store for API keys.
package memory

import (
	"context"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/BladiCreator/go-modular-auth-apikeys/store"
)

// Store implements store.Store using in-memory maps guarded by a sync.RWMutex.
type Store struct {
	mu         sync.RWMutex
	keysByID   map[string]*store.APIKey
	keysByHash map[string]*store.APIKey
}

var _ store.Store = (*Store)(nil)

// New constructs an empty in-memory API key store.
func New() *Store {
	return &Store{
		keysByID:   make(map[string]*store.APIKey),
		keysByHash: make(map[string]*store.APIKey),
	}
}

// Create persists a new API key record.
func (s *Store) Create(ctx context.Context, key *store.APIKey) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.keysByID[key.ID]; exists {
		return store.ErrConflict
	}
	if _, exists := s.keysByHash[key.KeyHash]; exists {
		return store.ErrConflict
	}

	cloned := cloneKey(key)
	s.keysByID[key.ID] = cloned
	s.keysByHash[key.KeyHash] = cloned
	return nil
}

// GetByID retrieves an API key by ID.
func (s *Store) GetByID(ctx context.Context, id string) (*store.APIKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	key, exists := s.keysByID[id]
	if !exists {
		return nil, store.ErrNotFound
	}
	return cloneKey(key), nil
}

// GetByHash retrieves an API key by its SHA-256 hash.
func (s *Store) GetByHash(ctx context.Context, keyHash string) (*store.APIKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	key, exists := s.keysByHash[keyHash]
	if !exists {
		return nil, store.ErrNotFound
	}
	return cloneKey(key), nil
}

// Update modifies an existing API key record.
func (s *Store) Update(ctx context.Context, key *store.APIKey) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	existing, exists := s.keysByID[key.ID]
	if !exists {
		return store.ErrNotFound
	}

	// Update hash lookup if hash changed
	if existing.KeyHash != key.KeyHash {
		delete(s.keysByHash, existing.KeyHash)
	}

	cloned := cloneKey(key)
	s.keysByID[key.ID] = cloned
	s.keysByHash[key.KeyHash] = cloned
	return nil
}

// Revoke sets RevokedAt on the specified key.
func (s *Store) Revoke(ctx context.Context, id string, revokedAt time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	key, exists := s.keysByID[id]
	if !exists {
		return store.ErrNotFound
	}

	key.RevokedAt = &revokedAt
	key.UpdatedAt = revokedAt
	return nil
}

// TouchLastUsed updates last used metadata on the key.
func (s *Store) TouchLastUsed(ctx context.Context, id string, at time.Time, ip string, ua string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	key, exists := s.keysByID[id]
	if !exists {
		return store.ErrNotFound
	}

	key.LastUsedAt = &at
	key.LastUsedIP = ip
	key.LastUsedUA = ua
	key.UpdatedAt = at
	return nil
}

// List queries matching keys according to filter criteria.
func (s *Store) List(ctx context.Context, filter store.ListFilter) ([]*store.APIKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []*store.APIKey
	for _, key := range s.keysByID {
		if filter.UserID != "" && key.UserID != filter.UserID {
			continue
		}
		if filter.OrganizationID != "" && key.OrganizationID != filter.OrganizationID {
			continue
		}
		if filter.ServiceID != "" && key.ServiceID != filter.ServiceID {
			continue
		}
		if !filter.IncludeRevoked && key.IsRevoked() {
			continue
		}
		results = append(results, cloneKey(key))
	}

	// Sort chronologically newest first
	slices.SortFunc(results, func(a, b *store.APIKey) int {
		if b.CreatedAt.After(a.CreatedAt) {
			return 1
		}
		if a.CreatedAt.After(b.CreatedAt) {
			return -1
		}
		return 0
	})

	if filter.Offset > 0 {
		if filter.Offset >= len(results) {
			return []*store.APIKey{}, nil
		}
		results = results[filter.Offset:]
	}

	if filter.Limit > 0 && len(results) > filter.Limit {
		results = results[:filter.Limit]
	}

	return results, nil
}

// Delete permanently removes an API key.
func (s *Store) Delete(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	key, exists := s.keysByID[id]
	if !exists {
		return store.ErrNotFound
	}

	delete(s.keysByID, id)
	delete(s.keysByHash, key.KeyHash)
	return nil
}

// DeleteExpired removes keys that expired before the specified time.
func (s *Store) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	count := 0
	for id, key := range s.keysByID {
		if key.ExpiresAt != nil && key.ExpiresAt.Before(before) {
			delete(s.keysByID, id)
			delete(s.keysByHash, key.KeyHash)
			count++
		}
	}
	return count, nil
}

func cloneKey(k *store.APIKey) *store.APIKey {
	if k == nil {
		return nil
	}
	cloned := *k
	cloned.Scopes = slices.Clone(k.Scopes)
	cloned.Permissions = slices.Clone(k.Permissions)
	cloned.Metadata = maps.Clone(k.Metadata)
	if k.ExpiresAt != nil {
		exp := *k.ExpiresAt
		cloned.ExpiresAt = &exp
	}
	if k.RevokedAt != nil {
		rev := *k.RevokedAt
		cloned.RevokedAt = &rev
	}
	if k.LastUsedAt != nil {
		lu := *k.LastUsedAt
		cloned.LastUsedAt = &lu
	}
	return &cloned
}
