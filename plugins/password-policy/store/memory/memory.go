// Package memory provides an in-memory thread-safe implementation of store.Store.
package memory

import (
	"context"
	"slices"
	"sync"

	"github.com/BladiCreator/go-modular-auth-password-policy/store"
)

// Store implements store.Store using in-memory slices protected by sync.RWMutex.
type Store struct {
	mu      sync.RWMutex
	history map[string][]*store.PasswordHistory // userID -> newest first
}

var _ store.Store = (*Store)(nil)

// New initializes an empty in-memory store.
func New() *Store {
	return &Store{
		history: make(map[string][]*store.PasswordHistory),
	}
}

func cloneHistory(h *store.PasswordHistory) *store.PasswordHistory {
	if h == nil {
		return nil
	}
	cp := *h
	return &cp
}

// SaveHistory persists a new historical password record, prepending it (newest first).
func (s *Store) SaveHistory(_ context.Context, entry *store.PasswordHistory) error {
	if entry == nil || entry.ID == "" || entry.UserID == "" {
		return store.ErrNotFound
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	list := s.history[entry.UserID]
	s.history[entry.UserID] = slices.Insert(list, 0, cloneHistory(entry))
	return nil
}

// GetHistory retrieves the most recent historical records up to limit.
func (s *Store) GetHistory(_ context.Context, userID string, limit int) ([]*store.PasswordHistory, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	list, exists := s.history[userID]
	if !exists || len(list) == 0 {
		return nil, nil
	}

	n := len(list)
	if limit > 0 && limit < n {
		n = limit
	}

	res := make([]*store.PasswordHistory, n)
	for i := 0; i < n; i++ {
		res[i] = cloneHistory(list[i])
	}
	return res, nil
}

// PruneHistory retains only keepCount most recent records.
func (s *Store) PruneHistory(_ context.Context, userID string, keepCount int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	list, exists := s.history[userID]
	if !exists || len(list) <= keepCount {
		return nil
	}

	if keepCount <= 0 {
		delete(s.history, userID)
		return nil
	}

	s.history[userID] = list[:keepCount]
	return nil
}

// DeleteHistoryByUser removes all history for a user.
func (s *Store) DeleteHistoryByUser(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.history, userID)
	return nil
}
