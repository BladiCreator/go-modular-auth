package memory

import (
	"bytes"
	"context"
	"encoding/hex"
	"sync"
	"time"

	"github.com/BladiCreator/go-modular-auth-passkeys/store"
)

// MemoryStore implements store.Store using in-memory data structures.
type MemoryStore struct {
	mu          sync.RWMutex
	credentials map[string]*store.Credential
}

var _ store.Store = (*MemoryStore)(nil)

// New constructs a new in-memory passkey store.
func New() *MemoryStore {
	return &MemoryStore{
		credentials: make(map[string]*store.Credential),
	}
}

func key(id []byte) string {
	return hex.EncodeToString(id)
}

func clone(c *store.Credential) *store.Credential {
	cp := *c
	cp.CredentialID = bytes.Clone(c.CredentialID)
	cp.PublicKey = bytes.Clone(c.PublicKey)
	cp.AAGUID = bytes.Clone(c.AAGUID)
	if c.LastUsedAt != nil {
		t := *c.LastUsedAt
		cp.LastUsedAt = &t
	}
	if c.RevokedAt != nil {
		t := *c.RevokedAt
		cp.RevokedAt = &t
	}
	return &cp
}

// SaveCredential stores a new passkey credential.
func (m *MemoryStore) SaveCredential(ctx context.Context, c *store.Credential) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	k := key(c.CredentialID)
	if _, exists := m.credentials[k]; exists {
		return store.ErrConflict
	}

	m.credentials[k] = clone(c)
	return nil
}

// GetCredentialByID returns a passkey credential by its binary ID.
func (m *MemoryStore) GetCredentialByID(ctx context.Context, credentialID []byte) (*store.Credential, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	c, ok := m.credentials[key(credentialID)]
	if !ok || !c.Active() {
		return nil, store.ErrNotFound
	}

	return clone(c), nil
}

// ListCredentialsByUser returns all active credentials belonging to a user.
func (m *MemoryStore) ListCredentialsByUser(ctx context.Context, userID string) ([]*store.Credential, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*store.Credential
	for _, c := range m.credentials {
		if c.UserID == userID && c.Active() {
			result = append(result, clone(c))
		}
	}
	return result, nil
}

// UpdateCredential updates mutable fields on an existing credential.
func (m *MemoryStore) UpdateCredential(ctx context.Context, c *store.Credential) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	k := key(c.CredentialID)
	existing, ok := m.credentials[k]
	if !ok || !existing.Active() {
		return store.ErrNotFound
	}

	m.credentials[k] = clone(c)
	return nil
}

// DeleteCredential removes or marks the credential as revoked.
func (m *MemoryStore) DeleteCredential(ctx context.Context, credentialID []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	k := key(credentialID)
	c, ok := m.credentials[k]
	if !ok {
		return store.ErrNotFound
	}

	now := time.Now()
	c.RevokedAt = &now
	delete(m.credentials, k)
	return nil
}
