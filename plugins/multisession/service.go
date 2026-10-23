package multisession

import (
	"context"
	"errors"
	"sort"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth/adapter"
	corecache "github.com/BladiCreator/go-modular-auth/cache"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
	"github.com/BladiCreator/go-modular-auth/plugins/multisession/cache"
	"github.com/BladiCreator/go-modular-auth/session"
	corestore "github.com/BladiCreator/go-modular-auth/store"
)

type service struct {
	cfg     Config
	ctx     *sdk.Context
	records *sdk.Repository[MetadataRecord]
	cache   *cache.Cache
}

var _ MultiSession = (*service)(nil)

func newService(ctx *sdk.Context, cfg Config) *service {
	cacheAdapter := cache.New(ctx.Cache(), cfg.MetadataCacheTTL)
	return &service{
		cfg:     cfg,
		ctx:     ctx,
		records: sdk.Model[MetadataRecord](ctx, ModelSessionMetadata),
		cache:   cacheAdapter,
	}
}

func metadataRecordToCached(r *MetadataRecord) *cache.CachedMetadataRecord {
	if r == nil {
		return nil
	}
	return &cache.CachedMetadataRecord{
		SessionID: r.SessionID,
		UserID:    r.UserID,
		Device: cache.CachedDeviceRecord{
			Name:      r.Device.Name,
			Type:      r.Device.Type,
			OS:        r.Device.OS,
			Browser:   r.Device.Browser,
			IPAddress: r.Device.IPAddress,
		},
		Custom:    r.Custom,
		CreatedAt: r.CreatedAt,
		UpdatedAt: r.UpdatedAt,
	}
}

func cachedToMetadataRecord(c *cache.CachedMetadataRecord) *MetadataRecord {
	if c == nil {
		return nil
	}
	return &MetadataRecord{
		SessionID: c.SessionID,
		UserID:    c.UserID,
		Device: DeviceRecord{
			Name:      c.Device.Name,
			Type:      c.Device.Type,
			OS:        c.Device.OS,
			Browser:   c.Device.Browser,
			IPAddress: c.Device.IPAddress,
		},
		Custom:    c.Custom,
		CreatedAt: c.CreatedAt,
		UpdatedAt: c.UpdatedAt,
	}
}

// ListSessions returns all active, valid sessions for a user.
func (s *service) ListSessions(ctx context.Context, userID string) ([]*session.Session, error) {
	if userID == "" {
		return nil, ErrInvalidInput
	}

	sessions, err := s.ctx.Store().Sessions().ListByUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	now := s.ctx.Now()
	active := make([]*session.Session, 0, len(sessions))
	for _, sess := range sessions {
		if sess.Valid(now) {
			active = append(active, sess)
		}
	}

	return active, nil
}

// ListDetailedSessions returns active sessions enriched with metadata and current session flag.
func (s *service) ListDetailedSessions(ctx context.Context, userID string, currentSessionID string) ([]*SessionDetail, error) {
	active, err := s.ListSessions(ctx, userID)
	if err != nil {
		return nil, err
	}

	details := make([]*SessionDetail, 0, len(active))
	for _, sess := range active {
		meta, _ := s.GetMetadata(ctx, sess.ID)
		if meta == nil {
			// Auto-infer device metadata from Session entity if no explicit metadata exists
			device := ParseUserAgent(sess.UserAgent, sess.IPAddress)
			meta = &Metadata{
				SessionID: sess.ID,
				UserID:    sess.UserID,
				Device:    device,
				CreatedAt: sess.CreatedAt,
				UpdatedAt: sess.CreatedAt,
			}
		}

		isCurrent := currentSessionID != "" && sess.ID == currentSessionID
		details = append(details, &SessionDetail{
			Session:   sess,
			Metadata:  meta,
			IsCurrent: isCurrent,
		})
	}

	return details, nil
}

// GetSession retrieves an active session by its ID.
func (s *service) GetSession(ctx context.Context, sessionID string) (*session.Session, error) {
	if sessionID == "" {
		return nil, ErrInvalidInput
	}

	sess, err := s.ctx.Store().Sessions().GetByID(ctx, sessionID)
	if errors.Is(err, corestore.ErrNotFound) {
		return nil, ErrSessionNotFound
	}
	if err != nil {
		return nil, err
	}

	now := s.ctx.Now()
	if !sess.Valid(now) {
		return nil, ErrSessionNotFound
	}

	return sess, nil
}

// GetDetailedSession retrieves an active session enriched with its metadata.
func (s *service) GetDetailedSession(ctx context.Context, sessionID string) (*SessionDetail, error) {
	sess, err := s.GetSession(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	meta, _ := s.GetMetadata(ctx, sess.ID)
	if meta == nil {
		device := ParseUserAgent(sess.UserAgent, sess.IPAddress)
		meta = &Metadata{
			SessionID: sess.ID,
			UserID:    sess.UserID,
			Device:    device,
			CreatedAt: sess.CreatedAt,
			UpdatedAt: sess.CreatedAt,
		}
	}

	return &SessionDetail{
		Session:  sess,
		Metadata: meta,
	}, nil
}

// RevokeSession revokes a specific session by ID.
// Guarantees Store is updated first, Cache is immediately purged, and events are emitted.
func (s *service) RevokeSession(ctx context.Context, sessionID string) error {
	if sessionID == "" {
		return ErrInvalidInput
	}

	sess, err := s.ctx.Store().Sessions().GetByID(ctx, sessionID)
	if errors.Is(err, corestore.ErrNotFound) {
		return ErrSessionNotFound
	}
	if err != nil {
		return err
	}

	// Idempotent and safe for concurrent calls
	if sess.Revoked() {
		s.invalidateSessionCache(ctx, sess)
		return nil
	}

	now := s.ctx.Now()

	// 1. Update Store first
	if err := s.ctx.Store().Sessions().Revoke(ctx, sess.ID, now); err != nil {
		return err
	}
	sess.RevokedAt = &now

	// 2. Immediately invalidate cache
	s.invalidateSessionCache(ctx, sess)

	// 3. Emit plugin event
	s.ctx.Events().Publish(ctx, auth.Event{
		Name:    EventSessionRevoked,
		Time:    now,
		Subject: sess.UserID,
		Payload: SessionRevokedPayload{
			SessionID: sess.ID,
			UserID:    sess.UserID,
			RevokedAt: now,
			Reason:    "user_requested",
		},
	})

	// 4. Emit core session revoked event
	s.ctx.Events().Publish(ctx, auth.Event{
		Name:    auth.EventSessionRevoked,
		Time:    now,
		Subject: sess.UserID,
		Payload: sess,
	})

	return nil
}

// RevokeOtherSessions revokes all active sessions for userID except currentSessionID.
func (s *service) RevokeOtherSessions(ctx context.Context, userID, currentSessionID string) error {
	if userID == "" || currentSessionID == "" {
		return ErrInvalidInput
	}

	// Verify current session ownership and validity
	current, err := s.ctx.Store().Sessions().GetByID(ctx, currentSessionID)
	if errors.Is(err, corestore.ErrNotFound) {
		return ErrSessionNotFound
	}
	if err != nil {
		return err
	}
	if current.UserID != userID {
		return ErrUnauthorized
	}
	if current.Revoked() {
		return ErrSessionAlreadyRevoked
	}

	now := s.ctx.Now()
	var revoked []*session.Session

	// Execute revocation atomically inside Store transaction
	err = s.ctx.Store().Transaction(ctx, func(txCtx context.Context) error {
		all, err := s.ctx.Store().Sessions().ListByUser(txCtx, userID)
		if err != nil {
			return err
		}

		for _, sess := range all {
			if sess.ID == currentSessionID || sess.Revoked() {
				continue
			}
			if err := s.ctx.Store().Sessions().Revoke(txCtx, sess.ID, now); err != nil {
				return err
			}
			sess.RevokedAt = &now
			revoked = append(revoked, sess)
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Invalidate caches and publish events post-commit
	for _, r := range revoked {
		s.invalidateSessionCache(ctx, r)
		s.ctx.Events().Publish(ctx, auth.Event{
			Name:    auth.EventSessionRevoked,
			Time:    now,
			Subject: userID,
			Payload: r,
		})
	}

	if len(revoked) > 0 {
		s.ctx.Events().Publish(ctx, auth.Event{
			Name:    EventSessionsRevoked,
			Time:    now,
			Subject: userID,
			Payload: SessionsRevokedPayload{
				UserID:          userID,
				RevokedCount:    len(revoked),
				ExceptSessionID: currentSessionID,
				RevokedAt:       now,
				Reason:          "revoke_others",
			},
		})
	}

	return nil
}

// RevokeAllSessions revokes every active session for userID.
func (s *service) RevokeAllSessions(ctx context.Context, userID string) error {
	if userID == "" {
		return ErrInvalidInput
	}

	now := s.ctx.Now()
	var revoked []*session.Session

	err := s.ctx.Store().Transaction(ctx, func(txCtx context.Context) error {
		var err error
		revoked, err = s.ctx.Store().Sessions().RevokeByUser(txCtx, userID, now)
		return err
	})
	if err != nil {
		return err
	}

	// Invalidate caches and publish events post-commit
	for _, r := range revoked {
		s.invalidateSessionCache(ctx, r)
		s.ctx.Events().Publish(ctx, auth.Event{
			Name:    auth.EventSessionRevoked,
			Time:    now,
			Subject: userID,
			Payload: r,
		})
	}

	if len(revoked) > 0 {
		s.ctx.Events().Publish(ctx, auth.Event{
			Name:    EventSessionsRevoked,
			Time:    now,
			Subject: userID,
			Payload: SessionsRevokedPayload{
				UserID:       userID,
				RevokedCount: len(revoked),
				RevokedAt:    now,
				Reason:       "revoke_all",
			},
		})
	}

	return nil
}

// SetMetadata persists device and custom metadata for a session.
func (s *service) SetMetadata(ctx context.Context, sessionID string, meta MetadataInput) error {
	if sessionID == "" {
		return ErrInvalidInput
	}

	sess, err := s.ctx.Store().Sessions().GetByID(ctx, sessionID)
	if errors.Is(err, corestore.ErrNotFound) {
		return ErrSessionNotFound
	}
	if err != nil {
		return err
	}

	now := s.ctx.Now()
	rec := &MetadataRecord{
		SessionID: sess.ID,
		UserID:    sess.UserID,
		Device: DeviceRecord{
			Name:      meta.Device.Name,
			Type:      meta.Device.Type,
			OS:        meta.Device.OS,
			Browser:   meta.Device.Browser,
			IPAddress: meta.Device.IPAddress,
		},
		Custom:    meta.Custom,
		CreatedAt: now,
		UpdatedAt: now,
	}

	// 1. Persistence first (upsert)
	existing, err := s.records.FindOne(ctx, adapter.Eq("session_id", sess.ID))
	if err == nil && existing != nil {
		_, err = s.records.Update(ctx, []adapter.Condition{adapter.Eq("session_id", sess.ID)}, map[string]any{
			"device":     rec.Device,
			"custom":     rec.Custom,
			"updated_at": now,
		})
		if err != nil {
			return err
		}
	} else {
		if err := s.records.Create(ctx, rec); err != nil {
			return err
		}
	}

	// 2. Cache update
	if s.cache != nil {
		s.cache.SetMetadata(ctx, metadataRecordToCached(rec))
	}

	// 3. Emit event
	s.ctx.Events().Publish(ctx, auth.Event{
		Name:    EventMetadataUpdated,
		Time:    now,
		Subject: sess.UserID,
		Payload: MetadataUpdatedPayload{
			SessionID: sess.ID,
			UserID:    sess.UserID,
			UpdatedAt: now,
		},
	})

	return nil
}

// GetMetadata retrieves metadata associated with a session.
func (s *service) GetMetadata(ctx context.Context, sessionID string) (*Metadata, error) {
	if sessionID == "" {
		return nil, ErrInvalidInput
	}

	// Check cache first (cache-aside)
	if s.cache != nil {
		if rec, ok := s.cache.GetMetadata(ctx, sessionID); ok {
			return mapRecordToMetadata(cachedToMetadataRecord(rec)), nil
		}
	}

	// Fallback to Persistence
	rec, err := s.records.FindOne(ctx, adapter.Eq("session_id", sessionID))
	if errors.Is(err, adapter.ErrNotFound) {
		return nil, ErrMetadataNotFound
	}
	if err != nil {
		return nil, err
	}

	if s.cache != nil {
		s.cache.SetMetadata(ctx, metadataRecordToCached(rec))
	}

	return mapRecordToMetadata(rec), nil
}

// onBeforeSessionCreate enforces maximum concurrent sessions before a new session is persisted.
// This hook runs inside the Store transaction of Core Auth.newSession.
func (s *service) onBeforeSessionCreate(ctx context.Context, newSess *session.Session) error {
	if s.cfg.MaxConcurrentSessions <= 0 {
		return nil
	}

	now := s.ctx.Now()
	all, err := s.ctx.Store().Sessions().ListByUser(ctx, newSess.UserID)
	if err != nil {
		return err
	}

	var active []*session.Session
	for _, existing := range all {
		if existing.Valid(now) {
			active = append(active, existing)
		}
	}

	if len(active) < s.cfg.MaxConcurrentSessions {
		return nil
	}

	if s.cfg.OverflowPolicy == OverflowReject {
		return ErrMaxConcurrentSessionsReached
	}

	// Policy: OverflowRevokeOldest (evict oldest active sessions to make room)
	sort.Slice(active, func(i, j int) bool {
		return active[i].CreatedAt.Before(active[j].CreatedAt)
	})

	excess := len(active) - s.cfg.MaxConcurrentSessions + 1
	for i := 0; i < excess; i++ {
		oldest := active[i]

		// Update Store first
		if err := s.ctx.Store().Sessions().Revoke(ctx, oldest.ID, now); err != nil {
			return err
		}
		oldest.RevokedAt = &now

		// Invalidate cache immediately
		s.invalidateSessionCache(ctx, oldest)

		// Emit eviction event
		s.ctx.Events().Publish(ctx, auth.Event{
			Name:    EventSessionEvicted,
			Time:    now,
			Subject: newSess.UserID,
			Payload: SessionEvictedPayload{
				SessionID: oldest.ID,
				UserID:    newSess.UserID,
				EvictedAt: now,
				Reason:    "max_concurrent_sessions",
			},
		})

		// Emit core session revoked event
		s.ctx.Events().Publish(ctx, auth.Event{
			Name:    auth.EventSessionRevoked,
			Time:    now,
			Subject: newSess.UserID,
			Payload: oldest,
		})
	}

	return nil
}

func (s *service) invalidateSessionCache(ctx context.Context, sess *session.Session) {
	if sess == nil {
		return
	}
	// Invalidate Core session cache entry if cache is configured
	if s.ctx.Cache() != nil && sess.TokenHash != "" {
		sc := corecache.NewSessionCache(s.ctx.Cache())
		_ = sc.Delete(ctx, sess.TokenHash)
	}
	// Invalidate metadata cache entry
	if s.cache != nil {
		s.cache.InvalidateMetadata(ctx, sess.ID)
	}
}

func mapRecordToMetadata(rec *MetadataRecord) *Metadata {
	if rec == nil {
		return nil
	}
	return &Metadata{
		SessionID: rec.SessionID,
		UserID:    rec.UserID,
		Device: DeviceMetadata{
			Name:      rec.Device.Name,
			Type:      rec.Device.Type,
			OS:        rec.Device.OS,
			Browser:   rec.Device.Browser,
			IPAddress: rec.Device.IPAddress,
		},
		Custom:    rec.Custom,
		CreatedAt: rec.CreatedAt,
		UpdatedAt: rec.UpdatedAt,
	}
}
