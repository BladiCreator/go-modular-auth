// Package memory implements an in-memory storage adapter for the SAML plugin.
package memory

import (
	"context"
	"sync"
	"time"

	"github.com/BladiCreator/go-modular-auth-saml/store"
)

type consumedEntry struct {
	providerID string
	expiresAt  time.Time
}

// Store provides a thread-safe, in-memory implementation of store.Store.
type Store struct {
	mu         sync.RWMutex
	idps        map[string]*store.IdPConfig
	entityIDs   map[string]string // entityID -> idpID
	requests    map[string]*store.RequestSession
	relayStates map[string]string // relayState -> requestID
	assertions  map[string]consumedEntry
}

var _ store.Store = (*Store)(nil)

// New initializes an empty in-memory SAML store.
func New() *Store {
	return &Store{
		idps:        make(map[string]*store.IdPConfig),
		entityIDs:   make(map[string]string),
		requests:    make(map[string]*store.RequestSession),
		relayStates: make(map[string]string),
		assertions:  make(map[string]consumedEntry),
	}
}

func cloneIdP(c *store.IdPConfig) *store.IdPConfig {
	if c == nil {
		return nil
	}
	cp := *c
	if c.Certificates != nil {
		cp.Certificates = append([]string(nil), c.Certificates...)
	}
	if c.AttributeMapping.Custom != nil {
		cp.AttributeMapping.Custom = make(map[string]string, len(c.AttributeMapping.Custom))
		for k, v := range c.AttributeMapping.Custom {
			cp.AttributeMapping.Custom[k] = v
		}
	}
	return &cp
}

func cloneRequest(r *store.RequestSession) *store.RequestSession {
	if r == nil {
		return nil
	}
	cp := *r
	return &cp
}

// SaveIdP persists a SAML Identity Provider configuration.
func (s *Store) SaveIdP(_ context.Context, cfg *store.IdPConfig) error {
	if cfg == nil || cfg.ID == "" || cfg.EntityID == "" {
		return store.ErrNotFound
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.idps[cfg.ID]; exists {
		return store.ErrConflict
	}
	if _, exists := s.entityIDs[cfg.EntityID]; exists {
		return store.ErrConflict
	}

	s.idps[cfg.ID] = cloneIdP(cfg)
	s.entityIDs[cfg.EntityID] = cfg.ID
	return nil
}

// GetIdP retrieves an IdP configuration by its provider ID.
func (s *Store) GetIdP(_ context.Context, id string) (*store.IdPConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cfg, exists := s.idps[id]
	if !exists {
		return nil, store.ErrNotFound
	}
	return cloneIdP(cfg), nil
}

// GetIdPByEntityID retrieves an IdP configuration by its SAML EntityID.
func (s *Store) GetIdPByEntityID(_ context.Context, entityID string) (*store.IdPConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	id, exists := s.entityIDs[entityID]
	if !exists {
		return nil, store.ErrNotFound
	}
	return cloneIdP(s.idps[id]), nil
}

// ListIdPs returns IdP configurations, optionally filtered by organization ID.
func (s *Store) ListIdPs(_ context.Context, orgID string) ([]*store.IdPConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*store.IdPConfig
	for _, cfg := range s.idps {
		if orgID == "" || cfg.OrganizationID == orgID {
			result = append(result, cloneIdP(cfg))
		}
	}
	return result, nil
}

// DeleteIdP removes an IdP configuration.
func (s *Store) DeleteIdP(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cfg, exists := s.idps[id]
	if !exists {
		return store.ErrNotFound
	}

	delete(s.entityIDs, cfg.EntityID)
	delete(s.idps, id)
	return nil
}

// SaveRequest stores an ephemeral SAML AuthnRequest state session.
func (s *Store) SaveRequest(_ context.Context, req *store.RequestSession) error {
	if req == nil || req.ID == "" {
		return store.ErrNotFound
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.requests[req.ID]; exists {
		return store.ErrConflict
	}

	s.requests[req.ID] = cloneRequest(req)
	if req.RelayState != "" {
		s.relayStates[req.RelayState] = req.ID
	}
	return nil
}

// GetRequest retrieves a request session by its ID without consuming it.
func (s *Store) GetRequest(_ context.Context, id string) (*store.RequestSession, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	req, exists := s.requests[id]
	if !exists {
		return nil, store.ErrNotFound
	}
	return cloneRequest(req), nil
}

// GetRequestByRelayState retrieves a request session by its RelayState token.
func (s *Store) GetRequestByRelayState(_ context.Context, relayState string) (*store.RequestSession, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	reqID, exists := s.relayStates[relayState]
	if !exists {
		return nil, store.ErrNotFound
	}
	req, exists := s.requests[reqID]
	if !exists {
		return nil, store.ErrNotFound
	}
	return cloneRequest(req), nil
}

// ConsumeRequest atomically marks a request session as redeemed to prevent replay attacks.
func (s *Store) ConsumeRequest(_ context.Context, id string, now time.Time) (*store.RequestSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, exists := s.requests[id]
	if !exists {
		return nil, store.ErrNotFound
	}

	if req.ConsumedAt != nil {
		return nil, store.ErrRequestConsumed
	}

	req.ConsumedAt = &now
	return cloneRequest(req), nil
}

// DeleteRequest removes a request session.
func (s *Store) DeleteRequest(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, exists := s.requests[id]
	if !exists {
		return store.ErrNotFound
	}
	if req.RelayState != "" {
		delete(s.relayStates, req.RelayState)
	}
	delete(s.requests, id)
	return nil
}

// PurgeExpiredRequests removes request sessions older than the cutoff timestamp.
func (s *Store) PurgeExpiredRequests(_ context.Context, before time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	count := 0
	for id, req := range s.requests {
		if !before.Before(req.ExpiresAt) {
			if req.RelayState != "" {
				delete(s.relayStates, req.RelayState)
			}
			delete(s.requests, id)
			count++
		}
	}
	return count, nil
}

// RecordAssertion tracks an assertion ID to prevent replay attacks within its validity window.
func (s *Store) RecordAssertion(_ context.Context, assertionID, providerID string, expiresAt, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if entry, exists := s.assertions[assertionID]; exists {
		if now.Before(entry.expiresAt) {
			return store.ErrAssertionReplayed
		}
	}

	s.assertions[assertionID] = consumedEntry{
		providerID: providerID,
		expiresAt:  expiresAt,
	}
	return nil
}

// PurgeExpiredAssertions removes recorded assertions that have passed their expiration timestamp.
func (s *Store) PurgeExpiredAssertions(_ context.Context, before time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	count := 0
	for id, entry := range s.assertions {
		if !before.Before(entry.expiresAt) {
			delete(s.assertions, id)
			count++
		}
	}
	return count, nil
}
