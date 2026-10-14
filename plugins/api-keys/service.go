package apikeys

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth/plugins/api-keys/cache"
	"github.com/BladiCreator/go-modular-auth/adapter"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapter/memory"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
	"github.com/BladiCreator/go-modular-auth/schema"
)

type service struct {
	ctx     *sdk.Context
	keys    *sdk.Repository[APIKey]
	limiter *cache.Limiter
	cfg     Config
	hooks   *Hooks
}

var _ APIKeys = (*service)(nil)

func newService(ctx *sdk.Context, cfg Config) *service {
	if ctx == nil {
		memAdapter := adaptermem.New()
		s := schema.New()
		_ = RegisterSchema(s)
		_ = memAdapter.RegisterSchema(context.Background(), s)
		ctx = sdk.NewTestContext(memAdapter, nil, nil)
	}

	var limiter *cache.Limiter
	if ctx.Cache() != nil {
		limiter = cache.NewLimiter(
			ctx.Cache(),
			cfg.MaxFailedAttempts,
			cfg.BruteForceWindow,
			cfg.CacheTTL,
		)
	} else {
		limiter = cache.NewLimiter(
			nil,
			cfg.MaxFailedAttempts,
			cfg.BruteForceWindow,
			cfg.CacheTTL,
		)
	}

	return &service{
		ctx:     ctx,
		keys:    sdk.Model[APIKey](ctx, ModelAPIKeys),
		limiter: limiter,
		cfg:     cfg,
		hooks:   &Hooks{},
	}
}

func (s *service) Hooks() *Hooks {
	return s.hooks
}

func (s *service) now() time.Time {
	if s.ctx != nil {
		return s.ctx.Now()
	}
	return time.Now().UTC()
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

	now := s.now()

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

	key := &APIKey{
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

	if err := s.keys.Create(ctx, key); err != nil {
		if errors.Is(err, adapter.ErrConflict) {
			return nil, ErrConflict
		}
		return nil, fmt.Errorf("apikeys: failed to persist API key: %w", err)
	}

	if s.ctx != nil && s.ctx.Events() != nil {
		s.ctx.Events().Publish(ctx, auth.Event{
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
	}

	result := &CreateResult{
		Key:    key,
		RawKey: rawKey,
	}

	s.hooks.afterCreate.run(ctx, key)
	return result, nil
}

func (s *service) Get(ctx context.Context, id string) (*APIKey, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, fmt.Errorf("%w: ID cannot be empty", ErrInvalidInput)
	}

	key, err := s.keys.FindOne(ctx, adapter.Eq("id", id))
	if err != nil {
		if errors.Is(err, adapter.ErrNotFound) {
			return nil, ErrKeyNotFound
		}
		return nil, err
	}
	return key, nil
}

func (s *service) List(ctx context.Context, filter ListFilter) ([]*APIKey, error) {
	where := make([]adapter.Condition, 0)
	if filter.UserID != "" {
		where = append(where, adapter.Eq("user_id", filter.UserID))
	}
	if filter.OrganizationID != "" {
		where = append(where, adapter.Eq("organization_id", filter.OrganizationID))
	}
	if filter.ServiceID != "" {
		where = append(where, adapter.Eq("service_id", filter.ServiceID))
	}
	if !filter.IncludeRevoked {
		where = append(where, adapter.IsNull("revoked_at"))
	}

	keys, err := s.keys.FindMany(ctx, adapter.Query{
		Where:  where,
		Limit:  filter.Limit,
		Offset: filter.Offset,
		SortBy: "created_at",
		Desc:   true,
	})
	if err != nil {
		return nil, err
	}

	results := make([]*APIKey, len(keys))
	for i := range keys {
		results[i] = &keys[i]
	}
	return results, nil
}

func (s *service) Revoke(ctx context.Context, id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("%w: ID cannot be empty", ErrInvalidInput)
	}

	if err := s.hooks.beforeRevoke.run(ctx, &id); err != nil {
		return err
	}

	key, err := s.keys.FindOne(ctx, adapter.Eq("id", id))
	if err != nil {
		if errors.Is(err, adapter.ErrNotFound) {
			return ErrKeyNotFound
		}
		return err
	}

	now := s.now()
	if !key.IsRevoked() {
		_, err := s.keys.Update(ctx, []adapter.Condition{
			adapter.Eq("id", id),
			adapter.IsNull("revoked_at"),
		}, map[string]any{
			"revoked_at": now,
			"updated_at": now,
		})
		if err != nil {
			return err
		}
		key.RevokedAt = &now
		key.UpdatedAt = now
	}

	// Immediate cache invalidation
	if s.limiter != nil {
		_ = s.limiter.Invalidate(ctx, key.ID, key.KeyHash)
	}

	if s.ctx != nil && s.ctx.Events() != nil {
		s.ctx.Events().Publish(ctx, auth.Event{
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
	}

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

	oldKey, err := s.keys.FindOne(ctx, adapter.Eq("id", id))
	if err != nil {
		if errors.Is(err, adapter.ErrNotFound) {
			return nil, ErrKeyNotFound
		}
		return nil, err
	}

	now := s.now()
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
		newExpiresAt = oldKey.ExpiresAt
	}

	rawKey, publicPrefix, keyHash, err := GenerateRawKey(s.cfg.KeyPrefix)
	if err != nil {
		return nil, err
	}

	newKey := &APIKey{
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

	if err := s.keys.Create(ctx, newKey); err != nil {
		return nil, fmt.Errorf("apikeys: failed to persist rotated key: %w", err)
	}

	var gracePeriodEnd *time.Time
	if rotCfg.gracePeriod > 0 {
		grace := now.Add(rotCfg.gracePeriod)
		gracePeriodEnd = &grace
		oldKey.ExpiresAt = &grace
		oldKey.UpdatedAt = now
		_, err := s.keys.Update(ctx, []adapter.Condition{adapter.Eq("id", oldKey.ID)}, map[string]any{
			"expires_at": grace,
			"updated_at": now,
		})
		if err != nil {
			return nil, fmt.Errorf("apikeys: failed to update old key grace period: %w", err)
		}
		if s.limiter != nil {
			_ = s.limiter.SetKey(ctx, toCacheRecord(oldKey))
		}
	} else {
		_, err := s.keys.Update(ctx, []adapter.Condition{
			adapter.Eq("id", oldKey.ID),
			adapter.IsNull("revoked_at"),
		}, map[string]any{
			"revoked_at": now,
			"updated_at": now,
		})
		if err != nil {
			return nil, fmt.Errorf("apikeys: failed to revoke old key: %w", err)
		}
		oldKey.RevokedAt = &now
		oldKey.UpdatedAt = now
		if s.limiter != nil {
			_ = s.limiter.Invalidate(ctx, oldKey.ID, oldKey.KeyHash)
		}
	}

	result := &RotateResult{
		NewKey: newKey,
		RawKey: rawKey,
		OldKey: oldKey,
	}

	if s.ctx != nil && s.ctx.Events() != nil {
		s.ctx.Events().Publish(ctx, auth.Event{
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
	}

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

	clientIdentifier := authCfg.ipAddress
	if s.limiter != nil {
		if blocked, _ := s.limiter.CheckRateLimit(ctx, clientIdentifier); blocked {
			return nil, ErrRateLimited
		}
	}

	if err := s.hooks.beforeAuthenticate.run(ctx, &rawKey); err != nil {
		return nil, err
	}

	keyHash := HashKey(rawKey)
	now := s.now()

	var key *APIKey
	if s.limiter != nil {
		cached, err := s.limiter.GetKey(ctx, keyHash)
		if err == nil && cached != nil {
			key = fromCacheRecord(cached)
		}
	}

	if key == nil {
		var err error
		key, err = s.keys.FindOne(ctx, adapter.Eq("key_hash", keyHash))
		if err != nil {
			DummyHashVerification(rawKey)
			if s.limiter != nil {
				_ = s.limiter.RecordFailure(ctx, clientIdentifier)
			}
			if errors.Is(err, adapter.ErrNotFound) {
				return nil, ErrInvalidKey
			}
			return nil, err
		}
	}

	if !ConstantTimeEqual(key.KeyHash, keyHash) {
		DummyHashVerification(rawKey)
		if s.limiter != nil {
			_ = s.limiter.RecordFailure(ctx, clientIdentifier)
		}
		return nil, ErrInvalidKey
	}

	if key.IsRevoked() {
		if s.limiter != nil {
			_ = s.limiter.Invalidate(ctx, key.ID, key.KeyHash)
		}
		return nil, ErrKeyRevoked
	}

	if key.IsExpired(now) {
		if s.limiter != nil {
			_ = s.limiter.Invalidate(ctx, key.ID, key.KeyHash)
		}
		return nil, ErrKeyExpired
	}

	if len(authCfg.requiredScopes) > 0 && !key.HasAllScopes(authCfg.requiredScopes...) {
		return nil, ErrInsufficientScope
	}

	if len(authCfg.requiredPermissions) > 0 && !key.HasAllPermissions(authCfg.requiredPermissions...) {
		return nil, ErrInsufficientPermission
	}

	if s.limiter != nil {
		_ = s.limiter.SetKey(ctx, toCacheRecord(key))
	}

	shouldTouch := key.LastUsedAt == nil || now.Sub(*key.LastUsedAt) >= s.cfg.TouchLastUsedThreshold
	if shouldTouch {
		_, _ = s.keys.Update(ctx, []adapter.Condition{adapter.Eq("id", key.ID)}, map[string]any{
			"last_used_at": now,
			"last_used_ip": authCfg.ipAddress,
			"last_used_ua": authCfg.userAgent,
		})
		key.LastUsedAt = &now
		key.LastUsedIP = authCfg.ipAddress
		key.LastUsedUA = authCfg.userAgent
	}

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

	if s.ctx != nil && s.ctx.Events() != nil {
		s.ctx.Events().Publish(ctx, auth.Event{
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
	}

	s.hooks.afterAuthenticate.run(ctx, result)
	return result, nil
}

func (s *service) Delete(ctx context.Context, id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("%w: ID cannot be empty", ErrInvalidInput)
	}

	key, err := s.keys.FindOne(ctx, adapter.Eq("id", id))
	if err != nil {
		if errors.Is(err, adapter.ErrNotFound) {
			return ErrKeyNotFound
		}
		return err
	}

	if _, err := s.keys.Delete(ctx, adapter.Eq("id", id)); err != nil {
		return err
	}

	if s.limiter != nil {
		_ = s.limiter.Invalidate(ctx, key.ID, key.KeyHash)
	}

	if s.ctx != nil && s.ctx.Events() != nil {
		s.ctx.Events().Publish(ctx, auth.Event{
			Name:    EventAPIKeyDeleted,
			Time:    s.now(),
			Subject: key.ID,
			Payload: DeletedPayload{
				ID:             key.ID,
				Prefix:         key.Prefix,
				UserID:         key.UserID,
				OrganizationID: key.OrganizationID,
				ServiceID:      key.ServiceID,
			},
		})
	}

	return nil
}

func (s *service) PurgeExpired(ctx context.Context) (int, error) {
	affected, err := s.keys.Delete(ctx, adapter.Lt("expires_at", s.now()), adapter.IsNotNull("expires_at"))
	return int(affected), err
}

func toCacheRecord(k *APIKey) *cache.KeyRecord {
	if k == nil {
		return nil
	}
	return &cache.KeyRecord{
		ID:             k.ID,
		Name:           k.Name,
		Prefix:         k.Prefix,
		KeyHash:        k.KeyHash,
		UserID:         k.UserID,
		OrganizationID: k.OrganizationID,
		ServiceID:      k.ServiceID,
		Scopes:         k.Scopes,
		Permissions:    k.Permissions,
		Metadata:       k.Metadata,
		ExpiresAt:      k.ExpiresAt,
		RevokedAt:      k.RevokedAt,
		LastUsedAt:     k.LastUsedAt,
		LastUsedIP:     k.LastUsedIP,
		LastUsedUA:     k.LastUsedUA,
		CreatedAt:      k.CreatedAt,
		UpdatedAt:      k.UpdatedAt,
	}
}

func fromCacheRecord(r *cache.KeyRecord) *APIKey {
	if r == nil {
		return nil
	}
	return &APIKey{
		ID:             r.ID,
		Name:           r.Name,
		Prefix:         r.Prefix,
		KeyHash:        r.KeyHash,
		UserID:         r.UserID,
		OrganizationID: r.OrganizationID,
		ServiceID:      r.ServiceID,
		Scopes:         r.Scopes,
		Permissions:    r.Permissions,
		Metadata:       r.Metadata,
		ExpiresAt:      r.ExpiresAt,
		RevokedAt:      r.RevokedAt,
		LastUsedAt:     r.LastUsedAt,
		LastUsedIP:     r.LastUsedIP,
		LastUsedUA:     r.LastUsedUA,
		CreatedAt:      r.CreatedAt,
		UpdatedAt:      r.UpdatedAt,
	}
}
