package memory

import (
	"context"
	"maps"
	"sync"

	"github.com/BladiCreator/go-modular-auth-multisession/store"
)

// Store is an in-memory, thread-safe implementation of store.Store.
type Store struct {
	mu      sync.RWMutex
	records map[string]*store.MetadataRecord // keyed by SessionID
}

var _ store.Store = (*Store)(nil)

// New creates a new in-memory metadata store.
func New() *Store {
	return &Store{
		records: make(map[string]*store.MetadataRecord),
	}
}

// Save persists or updates the metadata record.
func (s *Store) Save(_ context.Context, rec *store.MetadataRecord) error {
	if rec == nil || rec.SessionID == "" {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Clone to prevent external mutation
	cloned := *rec
	if rec.Custom != nil {
		cloned.Custom = maps.Clone(rec.Custom)
	}
	s.records[rec.SessionID] = &cloned
	return nil
}

// Get retrieves the metadata record by session ID.
func (s *Store) Get(_ context.Context, sessionID string) (*store.MetadataRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rec, ok := s.records[sessionID]
	if !ok {
		return nil, store.ErrNotFound
	}

	cloned := *rec
	if rec.Custom != nil {
		cloned.Custom = maps.Clone(rec.Custom)
	}
	return &cloned, nil
}

// Delete removes metadata for a session ID.
func (s *Store) Delete(_ context.Context, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.records, sessionID)
	return nil
}

// DeleteBySessionIDs removes metadata for multiple session IDs.
func (s *Store) DeleteBySessionIDs(_ context.Context, sessionIDs []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, id := range sessionIDs {
		delete(s.records, id)
	}
	return nil
}
