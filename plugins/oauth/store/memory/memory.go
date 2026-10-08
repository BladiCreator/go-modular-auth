// Package memory provides an in-memory, thread-safe implementation of store.Store.
package memory

import (
	"context"
	"maps"
	"sync"
	"time"

	"github.com/BladiCreator/go-modular-auth-oauth/store"
)

// Store implements store.Store entirely in memory.
type Store struct {
	mu     sync.RWMutex
	states map[string]*store.StateSession
	now    func() time.Time
}

var _ store.Store = (*Store)(nil)

// Option customizes the in-memory store.
type Option func(*Store)

// WithClock sets a custom clock function for deterministic testing.
func WithClock(clock func() time.Time) Option {
	return func(s *Store) {
		if clock != nil {
			s.now = clock
		}
	}
}

// New constructs an initialized in-memory OAuth store.
func New(opts ...Option) *Store {
	s := &Store{
		states: make(map[string]*store.StateSession),
		now:    time.Now,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// SaveState persists a newly initiated OAuth state session.
func (s *Store) SaveState(_ context.Context, state *store.StateSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.states[state.State]; exists {
		return store.ErrConflict
	}

	s.states[state.State] = cloneState(state)
	return nil
}

// GetState retrieves a state session without consuming it.
func (s *Store) GetState(_ context.Context, stateID string) (*store.StateSession, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	state, exists := s.states[stateID]
	if !exists {
		return nil, store.ErrNotFound
	}
	return cloneState(state), nil
}

// ConsumeState atomically marks the state session as consumed and returns it.
func (s *Store) ConsumeState(_ context.Context, stateID string, at time.Time) (*store.StateSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, exists := s.states[stateID]
	if !exists {
		return nil, store.ErrNotFound
	}

	if state.Expired(at) {
		return nil, store.ErrExpired
	}

	if state.Consumed() {
		return nil, store.ErrAlreadyConsumed
	}

	consumedAt := at
	state.ConsumedAt = &consumedAt

	return cloneState(state), nil
}

// DeleteState removes a state session by its state identifier.
func (s *Store) DeleteState(_ context.Context, stateID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.states, stateID)
	return nil
}

// DeleteExpiredStates purges state sessions that expired before the cutoff.
func (s *Store) DeleteExpiredStates(_ context.Context, before time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	count := 0
	for id, state := range s.states {
		if state.ExpiresAt.Before(before) {
			delete(s.states, id)
			count++
		}
	}
	return count, nil
}

func cloneState(s *store.StateSession) *store.StateSession {
	if s == nil {
		return nil
	}
	c := *s
	if s.Metadata != nil {
		c.Metadata = maps.Clone(s.Metadata)
	}
	if s.ConsumedAt != nil {
		t := *s.ConsumedAt
		c.ConsumedAt = &t
	}
	return &c
}
