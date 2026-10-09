package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	corecache "github.com/BladiCreator/go-modular-auth/cache"
)

// DefaultTTL is the default cache duration for authorization decisions.
const DefaultTTL = 5 * time.Minute

// CachedDecision is the stored authorization decision payload.
type CachedDecision struct {
	Allowed     bool      `json:"allowed"`
	Reason      string    `json:"reason,omitempty"`
	MatchedRole string    `json:"matched_role,omitempty"`
	Permission  string    `json:"permission"`
	CachedAt    time.Time `json:"cached_at"`
}

// Cache defines the semantic contract for caching authorization decisions.
type Cache interface {
	GetDecision(ctx context.Context, key string) (*CachedDecision, bool, error)
	SetDecision(ctx context.Context, key string, decision *CachedDecision, ttl time.Duration) error
	InvalidatePrincipal(ctx context.Context, principalSubject string) error
	InvalidateAll(ctx context.Context) error
}

// BuildKey constructs a namespaced cache key for an authorization query.
func BuildKey(principal auth.Principal, permission string, resType, resID, orgID, serviceID string) string {
	raw := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s",
		principal.Subject,
		string(principal.Type),
		permission,
		resType,
		resID,
		orgID,
		serviceID,
	)
	h := sha256.Sum256([]byte(raw))
	hashHex := hex.EncodeToString(h[:16])
	return corecache.Key("rbac", "eval", principal.Subject, hashHex)
}

// CoreCacheAdapter implements Cache using the shared GoModularAuth Core Cache adapter.
type CoreCacheAdapter struct {
	coreCache corecache.Cache
	defaultTTL time.Duration

	mu             sync.Mutex
	principalKeys  map[string]map[string]struct{}
}

var _ Cache = (*CoreCacheAdapter)(nil)

func NewCoreCacheAdapter(c corecache.Cache, defaultTTL time.Duration) *CoreCacheAdapter {
	if defaultTTL <= 0 {
		defaultTTL = DefaultTTL
	}
	return &CoreCacheAdapter{
		coreCache:     c,
		defaultTTL:    defaultTTL,
		principalKeys: make(map[string]map[string]struct{}),
	}
}

func (a *CoreCacheAdapter) GetDecision(ctx context.Context, key string) (*CachedDecision, bool, error) {
	if a.coreCache == nil {
		return nil, false, nil
	}
	var d CachedDecision
	err := a.coreCache.Get(ctx, key, &d)
	if err != nil {
		return nil, false, nil
	}
	return &d, true, nil
}

func (a *CoreCacheAdapter) SetDecision(ctx context.Context, key string, decision *CachedDecision, ttl time.Duration) error {
	if a.coreCache == nil {
		return nil
	}
	if ttl <= 0 {
		ttl = a.defaultTTL
	}
	if err := a.coreCache.Set(ctx, key, decision, ttl); err != nil {
		return err
	}

	// Track key by principal for targeted invalidation
	a.mu.Lock()
	defer a.mu.Unlock()
	parts := strings.Split(key, ":")
	if len(parts) >= 4 {
		subj := parts[3]
		if _, exists := a.principalKeys[subj]; !exists {
			a.principalKeys[subj] = make(map[string]struct{})
		}
		a.principalKeys[subj][key] = struct{}{}
	}
	return nil
}

func (a *CoreCacheAdapter) InvalidatePrincipal(ctx context.Context, principalSubject string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.coreCache == nil {
		return nil
	}

	keys, exists := a.principalKeys[principalSubject]
	if !exists {
		return nil
	}

	for k := range keys {
		_ = a.coreCache.Delete(ctx, k)
	}
	delete(a.principalKeys, principalSubject)
	return nil
}

func (a *CoreCacheAdapter) InvalidateAll(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.coreCache == nil {
		return nil
	}

	for _, keys := range a.principalKeys {
		for k := range keys {
			_ = a.coreCache.Delete(ctx, k)
		}
	}
	a.principalKeys = make(map[string]map[string]struct{})
	return nil
}

// MemoryCache provides a fast, standalone thread-safe in-memory cache for RBAC evaluations.
type MemoryCache struct {
	mu            sync.RWMutex
	items         map[string]*memoryItem
	principalKeys map[string]map[string]struct{}
	defaultTTL    time.Duration
}

type memoryItem struct {
	decision  CachedDecision
	expiresAt time.Time
}

var _ Cache = (*MemoryCache)(nil)

func NewMemoryCache(ttl time.Duration) *MemoryCache {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &MemoryCache{
		items:         make(map[string]*memoryItem),
		principalKeys: make(map[string]map[string]struct{}),
		defaultTTL:    ttl,
	}
}

func (m *MemoryCache) GetDecision(_ context.Context, key string) (*CachedDecision, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	it, exists := m.items[key]
	if !exists {
		return nil, false, nil
	}

	if time.Now().After(it.expiresAt) {
		return nil, false, nil
	}

	cp := it.decision
	return &cp, true, nil
}

func (m *MemoryCache) SetDecision(_ context.Context, key string, decision *CachedDecision, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if ttl <= 0 {
		ttl = m.defaultTTL
	}

	m.items[key] = &memoryItem{
		decision:  *decision,
		expiresAt: time.Now().Add(ttl),
	}
	return nil
}

func (m *MemoryCache) InvalidatePrincipal(_ context.Context, principalSubject string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Keys matching the prefix containing the principal
	prefix := corecache.Key("rbac", "eval", principalSubject)
	for k := range m.items {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			delete(m.items, k)
		}
	}
	return nil
}

func (m *MemoryCache) InvalidateAll(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.items = make(map[string]*memoryItem)
	m.principalKeys = make(map[string]map[string]struct{})
	return nil
}
