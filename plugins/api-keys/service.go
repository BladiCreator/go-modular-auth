package apikeys

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/BladiCreator/go-modular-auth-apikeys/cache"
	"github.com/BladiCreator/go-modular-auth-apikeys/store"
	auth "github.com/BladiCreator/go-modular-auth"
)

type service struct {
	host    *auth.Host
	store   store.Store
	limiter *cache.Limiter
	cfg     Config
	hooks   *Hooks
}

var _ APIKeys = (*service)(nil)

func newService(h *auth.Host, cfg Config) *service {
	limiter := cache.NewLimiter(
		h.Cache(),
		cfg.MaxFailedAttempts,
		cfg.BruteForceWindow,
		cfg.CacheTTL,
	)

	return &service{
		host:    h,
		store:   cfg.Store,
		limiter: limiter,
		cfg:     cfg,
		hooks:   &Hooks{},
	}
}

func (s *service) Hooks() *Hooks {
	return s.hooks
}

func (s *service) Create(ctx context.Context, in CreateInput) (*CreateResult, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return nil, fmt.Errorf("%w: name cannot be empty", ErrInvalidInput)
	}

	if err := s.hooks.beforeCreate.run(ctx, &in); err != nil {
		return nil, err
	}

	prefix := in.Prefix
	if prefix == "" {
		prefix = s.cfg.KeyPrefix
	}

	rawKey, publicPrefix, keyHash, err := GenerateRawKey(prefix)
	if err != nil {
		return nil, err
	}

	now := s.host.Now()

	var expiresAt *time.Time
	if in.ExpiresAt != nil {
		expiresAt = in.ExpiresAt
	} else if in.ExpiresIn > 0 {
		exp := now.Add(in.ExpiresIn)
		expiresAt = &exp
	} else if s.cfg.DefaultExpiresIn > 0 {
		exp := now.Add(s.cfg.DefaultExpiresIn)
		expiresAt = &exp
	}

	key := &store.APIKey{
		ID:             GenerateID("ak_"),
		Name:           name,
		Prefix:         publicPrefix,
		KeyHash:        keyHash,
		UserID:         strings.TrimSpace(in.UserID),
		OrganizationID: strings.TrimSpace(in.OrganizationID),
		ServiceID:      strings.TrimSpace(in.ServiceID),
		Scopes:         slices.Clone(in.Scopes),
		Permissions:    slices.Clone(in.Permissions),
		Metadata:       maps.Clone(in.Metadata),
		ExpiresAt:      expiresAt,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	if err := s.store.Create(ctx, key); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return nil, ErrConflict
		}
		return nil, fmt.Errorf("apikeys: failed to persist API key: %w", err)
	}

	s.host.Events().Publish(ctx, auth.Event{
		Name:    EventAPIKeyCreated,
		Time:    now,
		Subject: key.ID,
		Payload: CreatedPayload{
			ID:             key.ID,
			Name:           key.Name,
			Prefix:         key.Prefix,
			UserID:         key.UserID,
			OrganizationID: key.OrganizationID,
			ServiceID:      key.ServiceID,
			Scopes:         key.Scopes,
			Permissions:    key.Permissions,
			ExpiresAt:      key.ExpiresAt,
		},
	})

	s.hooks.afterCreate.run(ctx, key)

	return &CreateResult{
		Key:    key,
		RawKey: rawKey,
	}, nil
}

func (s *service) Get(ctx context.Context, id string) (*APIKey, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, fmt.Errorf("%w: ID cannot be empty", ErrInvalidInput)
	}

	key, err := s.store.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrKeyNotFound
		}
		return nil, err
	}
	return key, nil
}

func (s *service) List(ctx context.Context, filter ListFilter) ([]*APIKey, error) {
	return s.store.List(ctx, filter)
}

func (s *service) Revoke(ctx context.Context, id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("%w: ID cannot be empty", ErrInvalidInput)
	}

	if err := s.hooks.beforeRevoke.run(ctx, &id); err != nil {
		return err
	}

	key, err := s.store.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrKeyNotFound
		}
		return err
	}

	now := s.host.Now()
	if !key.IsRevoked() {
		if err := s.store.Revoke(ctx, id, now); err != nil {
			return err
		}
		key.RevokedAt = &now
		key.UpdatedAt = now
	}

	// Immediate cache invalidation
	_ = s.limiter.Invalidate(ctx, key.ID, key.KeyHash)

	s.host.Events().Publish(ctx, auth.Event{
		Name:    EventAPIKeyRevoked,
		Time:    now,
		Subject: key.ID,
		Payload: RevokedPayload{
			ID:             key.ID,
			Prefix:         key.Prefix,
			UserID:         key.UserID,
			OrganizationID: key.OrganizationID,
			ServiceID:      key.ServiceID,
			RevokedAt:      now,
		},
	})

	s.hooks.afterRevoke.run(ctx, key)
	return nil
}

func (s *service) Rotate(ctx context.Context, id string, opts ...RotateOption) (*RotateResult, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, fmt.Errorf("%w: ID cannot be empty", ErrInvalidInput)
	}

	if err := s.hooks.beforeRotate.run(ctx, &id); err != nil {
		return nil, err
	}

	oldKey, err := s.store.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrKeyNotFound
		}
		return nil, err
	}

	now := s.host.Now()
	if oldKey.IsRevoked() {
		return nil, ErrKeyRevoked
	}
	if oldKey.IsExpired(now) {
		return nil, ErrKeyExpired
	}

	var rotCfg rotateConfig
	for _, opt := range opts {
		opt(&rotCfg)
	}

	name := oldKey.Name
	if rotCfg.newName != nil && strings.TrimSpace(*rotCfg.newName) != "" {
		name = strings.TrimSpace(*rotCfg.newName)
	}

	scopes := oldKey.Scopes
	if rotCfg.newScopes != nil {
		scopes = rotCfg.newScopes
	}

	permissions := oldKey.Permissions
	if rotCfg.newPermissions != nil {
		permissions = rotCfg.newPermissions
	}

	metadata := maps.Clone(oldKey.Metadata)
	if rotCfg.newMetadata != nil {
		metadata = rotCfg.newMetadata
	}

	var newExpiresAt *time.Time
	if rotCfg.newExpiresIn != nil && *rotCfg.newExpiresIn > 0 {
		exp := now.Add(*rotCfg.newExpiresIn)
		newExpiresAt = &exp
	} else if oldKey.ExpiresAt != nil {
		// Retain remaining lifetime or calculate equivalent
		newExpiresAt = oldKey.ExpiresAt
	}

	rawKey, publicPrefix, keyHash, err := GenerateRawKey(s.cfg.KeyPrefix)
	if err != nil {
		return nil, err
	}

	newKey := &store.APIKey{
		ID:             GenerateID("ak_"),
		Name:           name,
		Prefix:         publicPrefix,
		KeyHash:        keyHash,
		UserID:         oldKey.UserID,
		OrganizationID: oldKey.OrganizationID,
		ServiceID:      oldKey.ServiceID,
		Scopes:         slices.Clone(scopes),
		Permissions:    slices.Clone(permissions),
		Metadata:       metadata,
		ExpiresAt:      newExpiresAt,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	if err := s.store.Create(ctx, newKey); err != nil {
		return nil, fmt.Errorf("apikeys: failed to persist rotated key: %w", err)
	}

	var gracePeriodEnd *time.Time
	if rotCfg.gracePeriod > 0 {
		// Old key remains valid during grace period
		grace := now.Add(rotCfg.gracePeriod)
		gracePeriodEnd = &grace
		oldKey.ExpiresAt = &grace
		oldKey.UpdatedAt = now
		if err := s.store.Update(ctx, oldKey); err != nil {
			return nil, fmt.Errorf("apikeys: failed to update old key grace period: %w", err)
		}
		// Refresh cache with new expiration
		_ = s.limiter.SetKey(ctx, oldKey)
	} else {
		// Immediately revoke old key
		if err := s.store.Revoke(ctx, oldKey.ID, now); err != nil {
			return nil, fmt.Errorf("apikeys: failed to revoke old key: %w", err)
		}
		oldKey.RevokedAt = &now
		oldKey.UpdatedAt = now
		_ = s.limiter.Invalidate(ctx, oldKey.ID, oldKey.KeyHash)
	}

	result := &RotateResult{
		NewKey: newKey,
		RawKey: rawKey,
		OldKey: oldKey,
	}

	s.host.Events().Publish(ctx, auth.Event{
		Name:    EventAPIKeyRotated,
		Time:    now,
		Subject: newKey.ID,
		Payload: RotatedPayload{
			OldKeyID:       oldKey.ID,
			NewKeyID:       newKey.ID,
			Prefix:         newKey.Prefix,
			UserID:         newKey.UserID,
			OrganizationID: newKey.OrganizationID,
			ServiceID:      newKey.ServiceID,
			GracePeriod:    gracePeriodEnd,
		},
	})

	s.hooks.afterRotate.run(ctx, result)
	return result, nil
}

func (s *service) Authenticate(ctx context.Context, rawKey string, opts ...AuthOption) (*AuthResult, error) {
	rawKey = strings.TrimSpace(rawKey)
	if rawKey == "" {
		return nil, ErrInvalidKey
	}

	var authCfg authConfig
	for _, opt := range opts {
		opt(&authCfg)
	}

	// 1. Brute-force check
	clientIdentifier := authCfg.ipAddress
	if blocked, _ := s.limiter.CheckRateLimit(ctx, clientIdentifier); blocked {
		return nil, ErrRateLimited
	}

	if err := s.hooks.beforeAuthenticate.run(ctx, &rawKey); err != nil {
		return nil, err
	}

	keyHash := HashKey(rawKey)
	now := s.host.Now()

	// 2. Cache lookup
	key, err := s.limiter.GetKey(ctx, keyHash)
	if err != nil {
		// Cache miss: query Store (source of truth)
		key, err = s.store.GetByHash(ctx, keyHash)
		if err != nil {
			// Equalize timing via dummy verification
			DummyHashVerification(rawKey)
			_ = s.limiter.RecordFailure(ctx, clientIdentifier)
			if errors.Is(err, store.ErrNotFound) {
				return nil, ErrInvalidKey
			}
			return nil, err
		}
	}

	// 3. Constant-time validation
	if !ConstantTimeEqual(key.KeyHash, keyHash) {
		DummyHashVerification(rawKey)
		_ = s.limiter.RecordFailure(ctx, clientIdentifier)
		return nil, ErrInvalidKey
	}

	// 4. Status checks
	if key.IsRevoked() {
		_ = s.limiter.Invalidate(ctx, key.ID, key.KeyHash)
		return nil, ErrKeyRevoked
	}

	if key.IsExpired(now) {
		_ = s.limiter.Invalidate(ctx, key.ID, key.KeyHash)
		return nil, ErrKeyExpired
	}

	// 5. Scopes and Permissions checks
	if len(authCfg.requiredScopes) > 0 && !key.HasAllScopes(authCfg.requiredScopes...) {
		return nil, ErrInsufficientScope
	}

	if len(authCfg.requiredPermissions) > 0 && !key.HasAllPermissions(authCfg.requiredPermissions...) {
		return nil, ErrInsufficientPermission
	}

	// 6. Update cache
	_ = s.limiter.SetKey(ctx, key)

	// 7. Last used telemetry update (debounced)
	shouldTouch := key.LastUsedAt == nil || now.Sub(*key.LastUsedAt) >= s.cfg.TouchLastUsedThreshold
	if shouldTouch {
		_ = s.store.TouchLastUsed(ctx, key.ID, now, authCfg.ipAddress, authCfg.userAgent)
		key.LastUsedAt = &now
		key.LastUsedIP = authCfg.ipAddress
		key.LastUsedUA = authCfg.userAgent
	}

	// 8. Resolve to Core Principal
	subject := key.ID
	if s.cfg.SubjectStrategy == SubjectStrategyOwner {
		if key.UserID != "" {
			subject = key.UserID
		} else if key.ServiceID != "" {
			subject = key.ServiceID
		}
	}

	principal := auth.Principal{
		Subject: subject,
		Type:    auth.PrincipalAPIKey,
	}

	result := &AuthResult{
		Principal: principal,
		Key:       key,
	}

	s.host.Events().Publish(ctx, auth.Event{
		Name:    EventAPIKeyAuthenticated,
		Time:    now,
		Subject: key.ID,
		Payload: AuthenticatedPayload{
			ID:             key.ID,
			Prefix:         key.Prefix,
			UserID:         key.UserID,
			OrganizationID: key.OrganizationID,
			ServiceID:      key.ServiceID,
			IPAddress:      authCfg.ipAddress,
			UserAgent:      authCfg.userAgent,
			PrincipalType:  string(principal.Type),
			Subject:        principal.Subject,
		},
	})

	s.hooks.afterAuthenticate.run(ctx, result)

	return result, nil
}

func (s *service) Delete(ctx context.Context, id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("%w: ID cannot be empty", ErrInvalidInput)
	}

	key, err := s.store.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrKeyNotFound
		}
		return err
	}

	if err := s.store.Delete(ctx, id); err != nil {
		return err
	}

	_ = s.limiter.Invalidate(ctx, key.ID, key.KeyHash)

	s.host.Events().Publish(ctx, auth.Event{
		Name:    EventAPIKeyDeleted,
		Time:    s.host.Now(),
		Subject: key.ID,
		Payload: DeletedPayload{
			ID:             key.ID,
			Prefix:         key.Prefix,
			UserID:         key.UserID,
			OrganizationID: key.OrganizationID,
			ServiceID:      key.ServiceID,
		},
	})

	return nil
}

func (s *service) PurgeExpired(ctx context.Context) (int, error) {
	return s.store.DeleteExpired(ctx, s.host.Now())
}
