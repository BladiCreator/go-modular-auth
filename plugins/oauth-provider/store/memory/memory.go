// Package memory provides an in-memory Store implementation for the OAuth 2.1 Provider.
package memory

import (
	"context"
	"sync"
	"time"

	"github.com/BladiCreator/go-modular-auth-oauth-provider/store"
)

// Store implements store.Store completely in-memory.
type Store struct {
	mu            sync.RWMutex
	clients       map[string]*store.Client
	codes         map[string]*store.AuthorizationCode // keyed by codeHash
	accessTokens  map[string]*store.AccessToken       // keyed by tokenHash
	refreshTokens map[string]*store.RefreshToken      // keyed by tokenHash
}

var _ store.Store = (*Store)(nil)

// New creates a new in-memory Store.
func New() *Store {
	return &Store{
		clients:       make(map[string]*store.Client),
		codes:         make(map[string]*store.AuthorizationCode),
		accessTokens:  make(map[string]*store.AccessToken),
		refreshTokens: make(map[string]*store.RefreshToken),
	}
}

func (s *Store) Clients() store.ClientStore { return &clientStore{s} }
func (s *Store) Codes() store.CodeStore     { return &codeStore{s} }
func (s *Store) Tokens() store.TokenStore   { return &tokenStore{s} }

func (s *Store) Transaction(ctx context.Context, fn func(ctx context.Context) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fn(ctx)
}

// --- ClientStore ---

type clientStore struct{ s *Store }

func (cs *clientStore) Create(ctx context.Context, c *store.Client) error {
	cs.s.mu.Lock()
	defer cs.s.mu.Unlock()

	if _, exists := cs.s.clients[c.ID]; exists {
		return store.ErrConflict
	}
	cp := *c
	cs.s.clients[c.ID] = &cp
	return nil
}

func (cs *clientStore) GetByID(ctx context.Context, id string) (*store.Client, error) {
	cs.s.mu.RLock()
	defer cs.s.mu.RUnlock()

	c, exists := cs.s.clients[id]
	if !exists {
		return nil, store.ErrNotFound
	}
	cp := *c
	return &cp, nil
}

func (cs *clientStore) Update(ctx context.Context, c *store.Client) error {
	cs.s.mu.Lock()
	defer cs.s.mu.Unlock()

	if _, exists := cs.s.clients[c.ID]; !exists {
		return store.ErrNotFound
	}
	cp := *c
	cs.s.clients[c.ID] = &cp
	return nil
}

func (cs *clientStore) Revoke(ctx context.Context, id string, now time.Time) error {
	cs.s.mu.Lock()
	defer cs.s.mu.Unlock()

	c, exists := cs.s.clients[id]
	if !exists {
		return store.ErrNotFound
	}
	c.Status = store.ClientStatusRevoked
	c.UpdatedAt = now
	return nil
}

func (cs *clientStore) Delete(ctx context.Context, id string) error {
	cs.s.mu.Lock()
	defer cs.s.mu.Unlock()

	if _, exists := cs.s.clients[id]; !exists {
		return store.ErrNotFound
	}
	delete(cs.s.clients, id)
	return nil
}

// --- CodeStore ---

type codeStore struct{ s *Store }

func (cos *codeStore) Create(ctx context.Context, c *store.AuthorizationCode) error {
	cos.s.mu.Lock()
	defer cos.s.mu.Unlock()

	if _, exists := cos.s.codes[c.CodeHash]; exists {
		return store.ErrConflict
	}
	cp := *c
	cos.s.codes[c.CodeHash] = &cp
	return nil
}

func (cos *codeStore) GetByHash(ctx context.Context, codeHash string) (*store.AuthorizationCode, error) {
	cos.s.mu.RLock()
	defer cos.s.mu.RUnlock()

	c, exists := cos.s.codes[codeHash]
	if !exists {
		return nil, store.ErrNotFound
	}
	cp := *c
	return &cp, nil
}

func (cos *codeStore) Consume(ctx context.Context, codeHash string, now time.Time) (*store.AuthorizationCode, error) {
	cos.s.mu.Lock()
	defer cos.s.mu.Unlock()

	c, exists := cos.s.codes[codeHash]
	if !exists {
		return nil, store.ErrNotFound
	}
	if c.ConsumedAt != nil {
		return nil, store.ErrConflict
	}
	c.ConsumedAt = &now
	cp := *c
	return &cp, nil
}

func (cos *codeStore) DeleteExpired(ctx context.Context, now time.Time) (int, error) {
	cos.s.mu.Lock()
	defer cos.s.mu.Unlock()

	count := 0
	for h, c := range cos.s.codes {
		if !now.Before(c.ExpiresAt) {
			delete(cos.s.codes, h)
			count++
		}
	}
	return count, nil
}

// --- TokenStore ---

type tokenStore struct{ s *Store }

func (ts *tokenStore) CreateAccessToken(ctx context.Context, t *store.AccessToken) error {
	ts.s.mu.Lock()
	defer ts.s.mu.Unlock()

	if _, exists := ts.s.accessTokens[t.TokenHash]; exists {
		return store.ErrConflict
	}
	cp := *t
	ts.s.accessTokens[t.TokenHash] = &cp
	return nil
}

func (ts *tokenStore) GetAccessTokenByHash(ctx context.Context, tokenHash string) (*store.AccessToken, error) {
	ts.s.mu.RLock()
	defer ts.s.mu.RUnlock()

	t, exists := ts.s.accessTokens[tokenHash]
	if !exists {
		return nil, store.ErrNotFound
	}
	cp := *t
	return &cp, nil
}

func (ts *tokenStore) RevokeAccessToken(ctx context.Context, tokenHash string, now time.Time) error {
	ts.s.mu.Lock()
	defer ts.s.mu.Unlock()

	t, exists := ts.s.accessTokens[tokenHash]
	if !exists {
		return store.ErrNotFound
	}
	t.RevokedAt = &now
	return nil
}

func (ts *tokenStore) CreateRefreshToken(ctx context.Context, t *store.RefreshToken) error {
	ts.s.mu.Lock()
	defer ts.s.mu.Unlock()

	if _, exists := ts.s.refreshTokens[t.TokenHash]; exists {
		return store.ErrConflict
	}
	cp := *t
	ts.s.refreshTokens[t.TokenHash] = &cp
	return nil
}

func (ts *tokenStore) GetRefreshTokenByHash(ctx context.Context, tokenHash string) (*store.RefreshToken, error) {
	ts.s.mu.RLock()
	defer ts.s.mu.RUnlock()

	t, exists := ts.s.refreshTokens[tokenHash]
	if !exists {
		return nil, store.ErrNotFound
	}
	cp := *t
	return &cp, nil
}

func (ts *tokenStore) RevokeRefreshToken(ctx context.Context, tokenHash string, now time.Time) error {
	ts.s.mu.Lock()
	defer ts.s.mu.Unlock()

	t, exists := ts.s.refreshTokens[tokenHash]
	if !exists {
		return store.ErrNotFound
	}
	t.RevokedAt = &now
	return nil
}

func (ts *tokenStore) RevokeTokensByClient(ctx context.Context, clientID string, now time.Time) error {
	ts.s.mu.Lock()
	defer ts.s.mu.Unlock()

	for _, t := range ts.s.accessTokens {
		if t.ClientID == clientID && t.RevokedAt == nil {
			t.RevokedAt = &now
		}
	}
	for _, t := range ts.s.refreshTokens {
		if t.ClientID == clientID && t.RevokedAt == nil {
			t.RevokedAt = &now
		}
	}
	return nil
}

func (ts *tokenStore) RevokeTokensByUser(ctx context.Context, userID string, now time.Time) error {
	ts.s.mu.Lock()
	defer ts.s.mu.Unlock()

	for _, t := range ts.s.accessTokens {
		if t.UserID == userID && t.RevokedAt == nil {
			t.RevokedAt = &now
		}
	}
	for _, t := range ts.s.refreshTokens {
		if t.UserID == userID && t.RevokedAt == nil {
			t.RevokedAt = &now
		}
	}
	return nil
}

func (ts *tokenStore) DeleteExpired(ctx context.Context, now time.Time) (int, error) {
	ts.s.mu.Lock()
	defer ts.s.mu.Unlock()

	count := 0
	for h, t := range ts.s.accessTokens {
		if !now.Before(t.ExpiresAt) {
			delete(ts.s.accessTokens, h)
			count++
		}
	}
	for h, t := range ts.s.refreshTokens {
		if !now.Before(t.ExpiresAt) {
			delete(ts.s.refreshTokens, h)
			count++
		}
	}
	return count, nil
}
