// Package memory implements an in-memory store.Store for local development and testing.
package memory

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/BladiCreator/go-modular-auth-device-authorization/store"
)

type dataState struct {
	byID             map[string]*store.DeviceGrant
	byDeviceCodeHash map[string]string // hash -> ID
	byUserCode       map[string]string // user_code -> ID
}

func newDataState() *dataState {
	return &dataState{
		byID:             make(map[string]*store.DeviceGrant),
		byDeviceCodeHash: make(map[string]string),
		byUserCode:       make(map[string]string),
	}
}

func (s *dataState) clone() *dataState {
	c := newDataState()
	for k, v := range s.byDeviceCodeHash {
		c.byDeviceCodeHash[k] = v
	}
	for k, v := range s.byUserCode {
		c.byUserCode[k] = v
	}
	for k, v := range s.byID {
		copied := *v
		if v.LastPolledAt != nil {
			t := *v.LastPolledAt
			copied.LastPolledAt = &t
		}
		if v.AuthorizedAt != nil {
			t := *v.AuthorizedAt
			copied.AuthorizedAt = &t
		}
		if v.ConsumedAt != nil {
			t := *v.ConsumedAt
			copied.ConsumedAt = &t
		}
		if v.Metadata != nil {
			meta := make(map[string]string, len(v.Metadata))
			for mk, mv := range v.Metadata {
				meta[mk] = mv
			}
			copied.Metadata = meta
		}
		c.byID[k] = &copied
	}
	return c
}

// Store provides an in-memory implementation of store.Store.
type Store struct {
	mu   sync.RWMutex
	txMu sync.Mutex
	data *dataState
}

var _ store.Store = (*Store)(nil)

// New returns an initialized in-memory device authorization store.
func New() *Store {
	return &Store{
		data: newDataState(),
	}
}

// Transaction runs fn inside an isolated transaction with snapshot rollback.
func (s *Store) Transaction(ctx context.Context, fn func(ctx context.Context) error) error {
	s.txMu.Lock()
	defer s.txMu.Unlock()

	s.mu.Lock()
	snapshot := s.data.clone()
	s.mu.Unlock()

	if err := fn(ctx); err != nil {
		s.mu.Lock()
		s.data = snapshot
		s.mu.Unlock()
		return err
	}
	return nil
}

// Create persists a new device grant.
func (s *Store) Create(ctx context.Context, grant *store.DeviceGrant) error {
	if grant == nil || grant.ID == "" || grant.DeviceCodeHash == "" || grant.UserCode == "" {
		return store.ErrConflict
	}

	normUserCode := strings.ToUpper(strings.TrimSpace(grant.UserCode))

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.data.byID[grant.ID]; exists {
		return store.ErrConflict
	}
	if _, exists := s.data.byDeviceCodeHash[grant.DeviceCodeHash]; exists {
		return store.ErrConflict
	}
	if _, exists := s.data.byUserCode[normUserCode]; exists {
		return store.ErrConflict
	}

	copied := *grant
	copied.UserCode = normUserCode
	if grant.Metadata != nil {
		meta := make(map[string]string, len(grant.Metadata))
		for k, v := range grant.Metadata {
			meta[k] = v
		}
		copied.Metadata = meta
	}

	s.data.byID[grant.ID] = &copied
	s.data.byDeviceCodeHash[grant.DeviceCodeHash] = grant.ID
	s.data.byUserCode[normUserCode] = grant.ID

	return nil
}

// GetByDeviceCodeHash retrieves grant by hash of device_code.
func (s *Store) GetByDeviceCodeHash(ctx context.Context, codeHash string) (*store.DeviceGrant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	id, ok := s.data.byDeviceCodeHash[codeHash]
	if !ok {
		return nil, store.ErrNotFound
	}

	g, ok := s.data.byID[id]
	if !ok {
		return nil, store.ErrNotFound
	}

	copied := *g
	return &copied, nil
}

// GetByUserCode retrieves grant by user_code.
func (s *Store) GetByUserCode(ctx context.Context, userCode string) (*store.DeviceGrant, error) {
	norm := strings.ToUpper(strings.TrimSpace(userCode))

	s.mu.RLock()
	defer s.mu.RUnlock()

	id, ok := s.data.byUserCode[norm]
	if !ok {
		return nil, store.ErrNotFound
	}

	g, ok := s.data.byID[id]
	if !ok {
		return nil, store.ErrNotFound
	}

	copied := *g
	return &copied, nil
}

// Update modifies mutable grant properties.
func (s *Store) Update(ctx context.Context, grant *store.DeviceGrant) error {
	if grant == nil || grant.ID == "" {
		return store.ErrNotFound
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	existing, ok := s.data.byID[grant.ID]
	if !ok {
		return store.ErrNotFound
	}

	copied := *grant
	if grant.Metadata != nil {
		meta := make(map[string]string, len(grant.Metadata))
		for k, v := range grant.Metadata {
			meta[k] = v
		}
		copied.Metadata = meta
	}

	*existing = copied
	return nil
}

// IncrementFailedAttempts increments failed attempt counter for a user code.
func (s *Store) IncrementFailedAttempts(ctx context.Context, userCode string) (int, error) {
	norm := strings.ToUpper(strings.TrimSpace(userCode))

	s.mu.Lock()
	defer s.mu.Unlock()

	id, ok := s.data.byUserCode[norm]
	if !ok {
		return 0, store.ErrNotFound
	}

	g, ok := s.data.byID[id]
	if !ok {
		return 0, store.ErrNotFound
	}

	g.FailedAttempts++
	g.UpdatedAt = time.Now()
	return g.FailedAttempts, nil
}

// Delete removes a grant by ID.
func (s *Store) Delete(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	g, ok := s.data.byID[id]
	if !ok {
		return store.ErrNotFound
	}

	delete(s.data.byDeviceCodeHash, g.DeviceCodeHash)
	delete(s.data.byUserCode, g.UserCode)
	delete(s.data.byID, id)
	return nil
}

// DeleteExpired removes grants expired before the given timestamp.
func (s *Store) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var toDelete []string
	for id, g := range s.data.byID {
		if g.ExpiresAt.Before(before) {
			toDelete = append(toDelete, id)
		}
	}

	for _, id := range toDelete {
		g := s.data.byID[id]
		delete(s.data.byDeviceCodeHash, g.DeviceCodeHash)
		delete(s.data.byUserCode, g.UserCode)
		delete(s.data.byID, id)
	}

	return len(toDelete), nil
}
