package challenge

import (
	"context"
	"sync"
	"time"
)

// MemoryStore provides a thread-safe in-memory implementation of challenge.Store.
type MemoryStore struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	now      func() time.Time
}

var _ Store = (*MemoryStore)(nil)

// NewMemoryStore constructs a new in-memory challenge store.
func NewMemoryStore(opts ...MemoryOption) *MemoryStore {
	ms := &MemoryStore{
		sessions: make(map[string]*Session),
		now:      time.Now,
	}
	for _, opt := range opts {
		opt(ms)
	}
	return ms
}

// MemoryOption customizes MemoryStore.
type MemoryOption func(*MemoryStore)

// WithClock sets a custom clock function for testing.
func WithClock(clock func() time.Time) MemoryOption {
	return func(ms *MemoryStore) {
		if clock != nil {
			ms.now = clock
		}
	}
}

// Save stores a new ceremony session.
func (ms *MemoryStore) Save(ctx context.Context, s *Session) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	cp := *s
	ms.sessions[s.ID] = &cp
	return nil
}

// Get retrieves a ceremony session without consuming it.
func (ms *MemoryStore) Get(ctx context.Context, id string) (*Session, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	s, ok := ms.sessions[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *s
	return &cp, nil
}

// Consume atomically marks the session as used and returns it.
func (ms *MemoryStore) Consume(ctx context.Context, id string) (*Session, error) {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	s, ok := ms.sessions[id]
	if !ok {
		return nil, ErrNotFound
	}

	now := ms.now()
	if s.Expired(now) {
		return nil, ErrExpired
	}

	if s.Consumed() {
		return nil, ErrAlreadyConsumed
	}

	consumedAt := now
	s.ConsumedAt = &consumedAt

	cp := *s
	return &cp, nil
}

// Delete removes a ceremony session.
func (ms *MemoryStore) Delete(ctx context.Context, id string) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	delete(ms.sessions, id)
	return nil
}

// DeleteExpired purges expired sessions.
func (ms *MemoryStore) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	count := 0
	for id, s := range ms.sessions {
		if s.ExpiresAt.Before(before) {
			delete(ms.sessions, id)
			count++
		}
	}
	return count, nil
}
