package apikey

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/plugin"
)

// PluginID is the unique string identifier for the API Key plugin ("api-key").
const PluginID = "api-key"

// Context key for storing authenticated ApiKey in request context if needed.
type contextKey string

const (
	ApiKeyContextKey contextKey = "apikey"
	UserContextKey   contextKey = "apikey_user"
)

// Plugin implements API Key authentication, verification, rate limiting, and management capabilities.
type Plugin struct {
	repo   Repository
	config Config
	ctx    *plugin.Context
}

// New instantiates a new API Key plugin instance configured with the specified repository and options.
func New(repo Repository, opts ...Option) *Plugin {
	cfg := DefaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}
	return &Plugin{
		repo:   repo,
		config: cfg,
	}
}

// ID returns the unique identifier for the API Key plugin ("api-key").
func (p *Plugin) ID() string {
	return PluginID
}

// Init initializes the plugin within the global GoModularAuth context.
func (p *Plugin) Init(ctx *plugin.Context) error {
	p.ctx = ctx
	return nil
}

// Config returns the active configuration settings of the API Key plugin.
func (p *Plugin) Config() Config {
	return p.config
}

// CreateKey issues and persists a new secure API Key record.
func (p *Plugin) CreateKey(ctx context.Context, params CreateApiKeyParams) (*CreateApiKeyResult, error) {
	if strings.TrimSpace(params.ReferenceID) == "" {
		return nil, ErrInvalidName
	}

	configID := params.ConfigID
	if configID == "" {
		configID = "default"
	}

	refType := params.ReferenceType
	if refType == "" {
		refType = "user"
	}

	prefix := p.config.DefaultPrefix
	if params.Prefix != "" {
		prefix = params.Prefix
	}

	keyLen := p.config.DefaultKeyLength
	if params.KeyLength > 0 {
		keyLen = params.KeyLength
	}

	var rawKey string
	var err error
	if p.config.CustomKeyGenerator != nil {
		rawKey, err = p.config.CustomKeyGenerator(keyLen, prefix)
	} else {
		rawKey, err = DefaultKeyGenerator(keyLen, prefix)
	}
	if err != nil {
		return nil, err
	}

	var storedKey string
	if p.config.DisableKeyHashing {
		storedKey = rawKey
	} else if p.config.CustomKeyHasher != nil {
		storedKey, err = p.config.CustomKeyHasher(rawKey)
	} else {
		storedKey, err = DefaultKeyHasher(rawKey)
	}
	if err != nil {
		return nil, err
	}

	startLen := 8
	if len(rawKey) < startLen {
		startLen = len(rawKey)
	}
	startChars := rawKey[:startLen]

	now := time.Now()
	var expiresAt *time.Time
	if params.ExpiresAt != nil {
		expiresAt = params.ExpiresAt
	} else if p.config.KeyExpiration != nil {
		exp := now.Add(*p.config.KeyExpiration)
		expiresAt = &exp
	}

	id, err := generateUniqueID()
	if err != nil {
		return nil, err
	}

	apiKey := &ApiKey{
		ID:                  id,
		ConfigID:            configID,
		Name:                params.Name,
		Start:               startChars,
		Prefix:              prefix,
		Key:                 storedKey,
		ReferenceID:         params.ReferenceID,
		ReferenceType:       refType,
		RefillInterval:      params.RefillInterval,
		RefillAmount:        params.RefillAmount,
		LastRefillAt:        nil,
		Enabled:             true,
		RateLimitEnabled:    params.RateLimitEnabled || p.config.RateLimitEnabled,
		RateLimitTimeWindow: params.RateLimitTimeWindow,
		RateLimitMax:        params.RateLimitMax,
		RequestCount:        0,
		Remaining:           params.Remaining,
		LastRequest:         nil,
		ExpiresAt:           expiresAt,
		CreatedAt:           now,
		UpdatedAt:           now,
		Permissions:         params.Permissions,
		Metadata:            params.Metadata,
	}

	if apiKey.RateLimitEnabled && apiKey.RateLimitTimeWindow == nil {
		windowMs := p.config.RateLimitTimeWindow.Milliseconds()
		apiKey.RateLimitTimeWindow = &windowMs
	}
	if apiKey.RateLimitEnabled && apiKey.RateLimitMax == nil {
		maxReq := p.config.RateLimitMax
		apiKey.RateLimitMax = &maxReq
	}

	if err := p.repo.CreateApiKey(ctx, apiKey); err != nil {
		return nil, err
	}

	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventApiKeyCreated, ctx, &ApiKeyCreatedPayload{
			ApiKey: apiKey,
			RawKey: rawKey,
		})
	}

	return &CreateApiKeyResult{
		ApiKey: apiKey,
		RawKey: rawKey,
	}, nil
}

// VerifyKey authenticates a raw API Key string against stored records, evaluating expiration, rate limits, and quota.
func (p *Plugin) VerifyKey(ctx context.Context, params VerifyApiKeyParams) (*VerifyApiKeyResult, error) {
	rawKey := strings.TrimSpace(params.Key)
	if rawKey == "" {
		return &VerifyApiKeyResult{Valid: false, Error: "empty api key"}, nil
	}

	var searchHash string
	var err error
	if p.config.DisableKeyHashing {
		searchHash = rawKey
	} else if p.config.CustomKeyHasher != nil {
		searchHash, err = p.config.CustomKeyHasher(rawKey)
	} else {
		searchHash, err = DefaultKeyHasher(rawKey)
	}
	if err != nil {
		return nil, err
	}

	apiKey, err := p.repo.FindApiKeyByKeyHash(ctx, searchHash)
	if err != nil || apiKey == nil {
		p.publishVerifyEvent(ctx, nil, false, ErrKeyNotFound.Error())
		return &VerifyApiKeyResult{Valid: false, Error: ErrKeyNotFound.Error()}, nil
	}

	if !apiKey.Enabled {
		p.publishVerifyEvent(ctx, apiKey, false, ErrKeyDisabled.Error())
		return &VerifyApiKeyResult{Valid: false, ApiKey: apiKey, Error: ErrKeyDisabled.Error()}, nil
	}

	now := time.Now()
	if apiKey.ExpiresAt != nil && now.After(*apiKey.ExpiresAt) {
		if p.ctx != nil && p.ctx.Events() != nil {
			p.ctx.Events().Publish(EventApiKeyExpired, ctx, &ApiKeyExpiredPayload{KeyID: apiKey.ID})
		}
		p.publishVerifyEvent(ctx, apiKey, false, ErrKeyExpired.Error())
		return &VerifyApiKeyResult{Valid: false, ApiKey: apiKey, Error: ErrKeyExpired.Error()}, nil
	}

	_ = CalculateRefill(apiKey, now)

	if apiKey.Remaining != nil && *apiKey.Remaining <= 0 {
		p.publishVerifyEvent(ctx, apiKey, false, ErrUsageExceeded.Error())
		return &VerifyApiKeyResult{Valid: false, ApiKey: apiKey, Error: ErrUsageExceeded.Error()}, nil
	}

	if !EvaluateRateLimit(apiKey, now) {
		p.publishVerifyEvent(ctx, apiKey, false, ErrRateLimitExceeded.Error())
		return &VerifyApiKeyResult{Valid: false, ApiKey: apiKey, Error: ErrRateLimitExceeded.Error()}, nil
	}

	if len(params.RequiredPermissions) > 0 && !CheckPermissions(apiKey.Permissions, params.RequiredPermissions) {
		p.publishVerifyEvent(ctx, apiKey, false, ErrUnauthorized.Error())
		return &VerifyApiKeyResult{Valid: false, ApiKey: apiKey, Error: ErrUnauthorized.Error()}, nil
	}

	// Update tracking fields
	apiKey.RequestCount++
	apiKey.LastRequest = &now
	if apiKey.Remaining != nil {
		*apiKey.Remaining--
	}
	apiKey.UpdatedAt = now

	// Save updates (asynchronously if DeferUpdates is enabled)
	if p.config.DeferUpdates {
		keyCopy := *apiKey
		go func(k ApiKey) {
			_ = p.repo.UpdateApiKey(context.Background(), &k)
		}(keyCopy)
	} else {
		_ = p.repo.UpdateApiKey(ctx, apiKey)
	}

	var user *entity.User
	if apiKey.ReferenceType == "user" && apiKey.ReferenceID != "" {
		user, _ = p.repo.GetUserByID(ctx, apiKey.ReferenceID)
	}

	p.publishVerifyEvent(ctx, apiKey, true, "")

	return &VerifyApiKeyResult{
		Valid:       true,
		ApiKey:      apiKey,
		User:        user,
		Permissions: apiKey.Permissions,
	}, nil
}

// GetKey retrieves an API Key by its database primary key ID.
func (p *Plugin) GetKey(ctx context.Context, params GetApiKeyParams) (*ApiKey, error) {
	if strings.TrimSpace(params.ID) == "" {
		return nil, ErrKeyNotFound
	}
	return p.repo.FindApiKeyByID(ctx, params.ID)
}

// UpdateKey updates configuration parameters of an existing API Key.
func (p *Plugin) UpdateKey(ctx context.Context, params UpdateApiKeyParams) (*ApiKey, error) {
	if strings.TrimSpace(params.ID) == "" {
		return nil, ErrKeyNotFound
	}
	apiKey, err := p.repo.FindApiKeyByID(ctx, params.ID)
	if err != nil || apiKey == nil {
		return nil, ErrKeyNotFound
	}

	if params.Name != nil {
		apiKey.Name = params.Name
	}
	if params.Enabled != nil {
		apiKey.Enabled = *params.Enabled
	}
	if params.RateLimitEnabled != nil {
		apiKey.RateLimitEnabled = *params.RateLimitEnabled
	}
	if params.RateLimitTimeWindow != nil {
		apiKey.RateLimitTimeWindow = params.RateLimitTimeWindow
	}
	if params.RateLimitMax != nil {
		apiKey.RateLimitMax = params.RateLimitMax
	}
	if params.Remaining != nil {
		apiKey.Remaining = params.Remaining
	}
	if params.RefillInterval != nil {
		apiKey.RefillInterval = params.RefillInterval
	}
	if params.RefillAmount != nil {
		apiKey.RefillAmount = params.RefillAmount
	}
	if params.ExpiresAt != nil {
		apiKey.ExpiresAt = params.ExpiresAt
	}
	if params.Permissions != nil {
		apiKey.Permissions = params.Permissions
	}
	if params.Metadata != nil {
		apiKey.Metadata = params.Metadata
	}
	apiKey.UpdatedAt = time.Now()

	if err := p.repo.UpdateApiKey(ctx, apiKey); err != nil {
		return nil, err
	}

	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventApiKeyUpdated, ctx, &ApiKeyUpdatedPayload{ApiKey: apiKey})
	}

	return apiKey, nil
}

// DeleteKey revokes and permanently deletes an API Key.
func (p *Plugin) DeleteKey(ctx context.Context, params DeleteApiKeyParams) error {
	if strings.TrimSpace(params.ID) == "" {
		return ErrKeyNotFound
	}
	if err := p.repo.DeleteApiKey(ctx, params.ID); err != nil {
		return err
	}

	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventApiKeyDeleted, ctx, &ApiKeyDeletedPayload{KeyID: params.ID})
	}

	return nil
}

// ListKeys fetches paginated API Keys belonging to a reference owner (user or organization).
func (p *Plugin) ListKeys(ctx context.Context, params ListApiKeysParams) (*ListApiKeysResult, error) {
	configID := params.ConfigID
	if configID == "" {
		configID = "default"
	}
	limit := params.Limit
	if limit <= 0 {
		limit = 20
	}

	keys, total, err := p.repo.ListApiKeysByReferenceID(ctx, configID, params.ReferenceID, limit, params.Offset)
	if err != nil {
		return nil, err
	}

	return &ListApiKeysResult{
		ApiKeys: keys,
		Total:   total,
	}, nil
}

// DeleteAllExpiredKeys purges all expired API Keys from persistent storage.
func (p *Plugin) DeleteAllExpiredKeys(ctx context.Context) (int64, error) {
	return p.repo.DeleteExpiredApiKeys(ctx)
}

func (p *Plugin) publishVerifyEvent(ctx context.Context, key *ApiKey, valid bool, errStr string) {
	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventApiKeyVerified, ctx, &ApiKeyVerifiedPayload{
			ApiKey: key,
			Valid:  valid,
			Error:  errStr,
		})
	}
}

func generateUniqueID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
