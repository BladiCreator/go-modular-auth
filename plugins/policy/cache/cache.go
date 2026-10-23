package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	corecache "github.com/BladiCreator/go-modular-auth/cache"
)

// DefaultTTL is the default cache duration for policy evaluation decisions.
const DefaultTTL = 5 * time.Minute

// CachedDecision is the stored authorization decision payload.
type CachedDecision struct {
	Effect    string         `json:"effect"`
	Reason    string         `json:"reason,omitempty"`
	Challenge map[string]any `json:"challenge,omitempty"`
	PolicyID  string         `json:"policy_id,omitempty"`
	CachedAt  time.Time      `json:"cached_at"`
}

// Cache defines the semantic contract for caching authorization decisions.
type Cache interface {
	GetDecision(ctx context.Context, key string) (*CachedDecision, bool, error)
	SetDecision(ctx context.Context, key string, decision *CachedDecision, ttl time.Duration) error
	InvalidatePrincipal(ctx context.Context, principalSubject string) error
	InvalidateResource(ctx context.Context, resourceType, resourceID string) error
	InvalidateAll(ctx context.Context) error
}

// BuildKey constructs a namespaced cache key for an evaluation request.
func BuildKey(principalSubject, principalType, organization, resType, resID, action string) string {
	raw := fmt.Sprintf("%s|%s|%s|%s|%s|%s",
		principalSubject,
		principalType,
		organization,
		resType,
		resID,
		action,
	)
	h := sha256.Sum256([]byte(raw))
	hashHex := hex.EncodeToString(h[:16])
	return corecache.Key("policy", "eval", principalSubject, resType, resID, hashHex)
}

// CoreCacheAdapter implements Cache using the shared GoModularAuth Core Cache.
type CoreCacheAdapter struct {
	coreCache     corecache.Cache
	defaultTTL    time.Duration
	mu            sync.Mutex
	principalKeys map[string]map[string]struct{}
	resourceKeys  map[string]map[string]struct{}
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
		resourceKeys:  make(map[string]map[string]struct{}),
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

	a.mu.Lock()
	defer a.mu.Unlock()

	parts := strings.Split(key, ":")
	// Format: gomodularauth:policy:eval:<subject>:<resType>:<resID>:<hash>
	if len(parts) >= 6 {
		subj := parts[3]
		resKey := parts[4] + ":" + parts[5]

		if _, exists := a.principalKeys[subj]; !exists {
			a.principalKeys[subj] = make(map[string]struct{})
		}
		a.principalKeys[subj][key] = struct{}{}

		if _, exists := a.resourceKeys[resKey]; !exists {
			a.resourceKeys[resKey] = make(map[string]struct{})
		}
		a.resourceKeys[resKey][key] = struct{}{}
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

func (a *CoreCacheAdapter) InvalidateResource(ctx context.Context, resourceType, resourceID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.coreCache == nil {
		return nil
	}

	resKey := resourceType + ":" + resourceID
	keys, exists := a.resourceKeys[resKey]
	if !exists {
		return nil
	}

	for k := range keys {
		_ = a.coreCache.Delete(ctx, k)
	}
	delete(a.resourceKeys, resKey)
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
	a.resourceKeys = make(map[string]map[string]struct{})
	return nil
}

// MemoryCache provides an in-memory thread-safe cache for policy evaluations.
type MemoryCache struct {
	mu         sync.RWMutex
	items      map[string]*memoryItem
	defaultTTL time.Duration
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
		items:      make(map[string]*memoryItem),
		defaultTTL: ttl,
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

	prefix := corecache.Key("policy", "eval", principalSubject)
	for k := range m.items {
		if strings.HasPrefix(k, prefix) {
			delete(m.items, k)
		}
	}
	return nil
}

func (m *MemoryCache) InvalidateResource(_ context.Context, resourceType, resourceID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	substr := ":" + resourceType + ":" + resourceID + ":"
	for k := range m.items {
		if strings.Contains(k, substr) {
			delete(m.items, k)
		}
	}
	return nil
}

func (m *MemoryCache) InvalidateAll(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.items = make(map[string]*memoryItem)
	return nil
}
