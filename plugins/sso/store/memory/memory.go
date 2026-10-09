// Package memory provides an in-memory implementation of the SSO store contract.
package memory

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/BladiCreator/go-modular-auth-sso/store"
)

// Store implements store.Store in-memory for testing, local development, and CI.
type Store struct {
	mu      sync.RWMutex
	configs map[string]*store.SSOConfig
	domains map[string]string // domain -> orgID:configID
	states  map[string]*store.SSOStateSession
}

var _ store.Store = (*Store)(nil)

// New initializes an empty in-memory SSO store.
func New() *Store {
	return &Store{
		configs: make(map[string]*store.SSOConfig),
		domains: make(map[string]string),
		states:  make(map[string]*store.SSOStateSession),
	}
}

func configKey(orgID, configID string) string {
	return orgID + ":" + configID
}

func cloneConfig(c *store.SSOConfig) *store.SSOConfig {
	if c == nil {
		return nil
	}
	cp := *c
	if c.Domains != nil {
		cp.Domains = append([]string(nil), c.Domains...)
	}
	if c.OIDC != nil {
		oidcCopy := *c.OIDC
		if c.OIDC.Scopes != nil {
			oidcCopy.Scopes = append([]string(nil), c.OIDC.Scopes...)
		}
		cp.OIDC = &oidcCopy
	}
	if c.SAML != nil {
		samlCopy := *c.SAML
		if c.SAML.Certificates != nil {
			samlCopy.Certificates = append([]string(nil), c.SAML.Certificates...)
		}
		cp.SAML = &samlCopy
	}
	if c.AttributeMapping.Custom != nil {
		cp.AttributeMapping.Custom = make(map[string]string, len(c.AttributeMapping.Custom))
		for k, v := range c.AttributeMapping.Custom {
			cp.AttributeMapping.Custom[k] = v
		}
	}
	return &cp
}

func cloneState(s *store.SSOStateSession) *store.SSOStateSession {
	if s == nil {
		return nil
	}
	cp := *s
	if s.Metadata != nil {
		cp.Metadata = make(map[string]string, len(s.Metadata))
		for k, v := range s.Metadata {
			cp.Metadata[k] = v
		}
	}
	return &cp
}

// SaveConfig stores a new SSO configuration and registers its domain mappings.
func (s *Store) SaveConfig(_ context.Context, cfg *store.SSOConfig) error {
	if cfg == nil || cfg.ID == "" || cfg.OrganizationID == "" {
		return store.ErrNotFound
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	key := configKey(cfg.OrganizationID, cfg.ID)
	if _, exists := s.configs[key]; exists {
		return store.ErrConflict
	}

	// Verify domain ownership
	for _, rawDomain := range cfg.Domains {
		d := strings.ToLower(strings.TrimSpace(rawDomain))
		if existingKey, claimed := s.domains[d]; claimed && existingKey != key {
			return store.ErrDomainClaimed
		}
	}

	// Register domains
	for _, rawDomain := range cfg.Domains {
		d := strings.ToLower(strings.TrimSpace(rawDomain))
		s.domains[d] = key
	}

	s.configs[key] = cloneConfig(cfg)
	return nil
}

// GetConfig retrieves an SSO configuration by its ID within an organization.
func (s *Store) GetConfig(_ context.Context, orgID, configID string) (*store.SSOConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cfg, exists := s.configs[configKey(orgID, configID)]
	if !exists {
		return nil, store.ErrNotFound
	}
	return cloneConfig(cfg), nil
}

// ListConfigsByOrganization returns all SSO configurations for a specific organization.
func (s *Store) ListConfigsByOrganization(_ context.Context, orgID string) ([]*store.SSOConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*store.SSOConfig
	for _, cfg := range s.configs {
		if cfg.OrganizationID == orgID {
			result = append(result, cloneConfig(cfg))
		}
	}
	return result, nil
}

// UpdateConfig updates an existing SSO configuration and syncs domain mappings.
func (s *Store) UpdateConfig(_ context.Context, cfg *store.SSOConfig) error {
	if cfg == nil || cfg.ID == "" || cfg.OrganizationID == "" {
		return store.ErrNotFound
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	key := configKey(cfg.OrganizationID, cfg.ID)
	old, exists := s.configs[key]
	if !exists {
		return store.ErrNotFound
	}

	// Check domain conflicts for new/updated domains
	for _, rawDomain := range cfg.Domains {
		d := strings.ToLower(strings.TrimSpace(rawDomain))
		if existingKey, claimed := s.domains[d]; claimed && existingKey != key {
			return store.ErrDomainClaimed
		}
	}

	// Remove old domains
	for _, rawDomain := range old.Domains {
		d := strings.ToLower(strings.TrimSpace(rawDomain))
		delete(s.domains, d)
	}

	// Re-register new domains
	for _, rawDomain := range cfg.Domains {
		d := strings.ToLower(strings.TrimSpace(rawDomain))
		s.domains[d] = key
	}

	s.configs[key] = cloneConfig(cfg)
	return nil
}

// DeleteConfig removes an SSO configuration and its registered domain mappings.
func (s *Store) DeleteConfig(_ context.Context, orgID, configID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := configKey(orgID, configID)
	old, exists := s.configs[key]
	if !exists {
		return store.ErrNotFound
	}

	for _, rawDomain := range old.Domains {
		d := strings.ToLower(strings.TrimSpace(rawDomain))
		delete(s.domains, d)
	}

	delete(s.configs, key)
	return nil
}

// GetConfigByDomain retrieves the active SSO configuration claiming the specified domain.
func (s *Store) GetConfigByDomain(_ context.Context, domain string) (*store.SSOConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	d := strings.ToLower(strings.TrimSpace(domain))
	cfgKey, exists := s.domains[d]
	if !exists {
		return nil, store.ErrNotFound
	}

	cfg, found := s.configs[cfgKey]
	if !found || !cfg.Enabled {
		return nil, store.ErrNotFound
	}

	return cloneConfig(cfg), nil
}

// SaveState stores a new ephemeral SSO state session.
func (s *Store) SaveState(_ context.Context, state *store.SSOStateSession) error {
	if state == nil || state.State == "" {
		return store.ErrNotFound
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.states[state.State]; exists {
		return store.ErrConflict
	}

	s.states[state.State] = cloneState(state)
	return nil
}

// GetState retrieves a state session without consuming it.
func (s *Store) GetState(_ context.Context, state string) (*store.SSOStateSession, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sess, exists := s.states[state]
	if !exists {
		return nil, store.ErrNotFound
	}
	return cloneState(sess), nil
}

// ConsumeState atomically marks a state session as consumed to prevent replay attacks.
func (s *Store) ConsumeState(_ context.Context, state string, now time.Time) (*store.SSOStateSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, exists := s.states[state]
	if !exists {
		return nil, store.ErrNotFound
	}

	if sess.ConsumedAt != nil {
		return nil, store.ErrStateConsumed
	}

	sess.ConsumedAt = &now
	return cloneState(sess), nil
}

// DeleteState removes a state session by its token.
func (s *Store) DeleteState(_ context.Context, state string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.states[state]; !exists {
		return store.ErrNotFound
	}
	delete(s.states, state)
	return nil
}

// PurgeExpiredStates deletes expired state sessions before the given timestamp.
func (s *Store) PurgeExpiredStates(_ context.Context, before time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	count := 0
	for key, sess := range s.states {
		if !before.Before(sess.ExpiresAt) {
			delete(s.states, key)
			count++
		}
	}
	return count, nil
}
