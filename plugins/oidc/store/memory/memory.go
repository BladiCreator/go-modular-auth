// Package memory provides an in-memory implementation of the OIDC Store interface.
package memory

import (
	"context"
	"sync"
	"time"

	"github.com/BladiCreator/go-modular-auth-oidc/store"
)

// Store implements store.Store using an in-memory thread-safe map.
type Store struct {
	mu     sync.RWMutex
	states map[string]*store.StateSession
}

var _ store.Store = (*Store)(nil)

// New creates an initialized in-memory OIDC state store.
func New() *Store {
	return &Store{
		states: make(map[string]*store.StateSession),
	}
}

// SaveState persists a newly initiated OIDC state session.
func (s *Store) SaveState(ctx context.Context, sess *store.StateSession) error {
	if sess == nil {
		return store.ErrNotFound
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.states[sess.State]; exists {
		return store.ErrConflict
	}

	s.states[sess.State] = cloneState(sess)
	return nil
}

// GetState retrieves a state session without consuming it.
func (s *Store) GetState(ctx context.Context, state string) (*store.StateSession, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sess, ok := s.states[state]
	if !ok {
		return nil, store.ErrNotFound
	}

	return cloneState(sess), nil
}

// ConsumeState atomically validates, retrieves, and marks a state session as consumed.
func (s *Store) ConsumeState(ctx context.Context, state string, now time.Time) (*store.StateSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.states[state]
	if !ok {
		return nil, store.ErrNotFound
	}

	if sess.IsConsumed() {
		return nil, store.ErrStateConsumed
	}

	t := now
	sess.ConsumedAt = &t

	return cloneState(sess), nil
}

// DeleteState removes a state session by its identifier.
func (s *Store) DeleteState(ctx context.Context, state string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.states[state]; !ok {
		return store.ErrNotFound
	}

	delete(s.states, state)
	return nil
}

// PurgeExpired removes all states expired before the specified instant.
func (s *Store) PurgeExpired(ctx context.Context, before time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	purged := 0
	for k, v := range s.states {
		if v.ExpiresAt.Before(before) {
			delete(s.states, k)
			purged++
		}
	}

	return purged, nil
}

func cloneState(in *store.StateSession) *store.StateSession {
	if in == nil {
		return nil
	}
	cp := *in
	if in.Metadata != nil {
		cp.Metadata = make(map[string]string, len(in.Metadata))
		for k, v := range in.Metadata {
			cp.Metadata[k] = v
		}
	}
	if in.ConsumedAt != nil {
		t := *in.ConsumedAt
		cp.ConsumedAt = &t
	}
	return &cp
}
