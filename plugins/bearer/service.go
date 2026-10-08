package bearer

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/BladiCreator/go-modular-auth-bearer/cache"
	"github.com/BladiCreator/go-modular-auth-bearer/store"
	auth "github.com/BladiCreator/go-modular-auth"
)

// service implements the Bearer capability interface.
type service struct {
	host   *auth.Host
	cfg    Config
	store  store.Store
	cache  *cache.Cache
	logger *slog.Logger
}

var _ Bearer = (*service)(nil)
var _ TransportAuthenticator = (*service)(nil)

func newService(host *auth.Host, cfg Config) *service {
	return &service{
		host:   host,
		cfg:    cfg,
		store:  cfg.Store,
		cache:  cache.New(host.Cache()),
		logger: host.Logger(),
	}
}

func (s *service) now() time.Time {
	if s.host != nil {
		return s.host.Now()
	}
	return time.Now().UTC()
}

// Authenticate validates bearer credentials and resolves the Principal.
// To prevent enumeration or leakage, secret credentials are never logged or echoed in errors.
func (s *service) Authenticate(ctx context.Context, in AuthenticateInput) (*AuthResult, error) {
	if err := ValidateTokenFormat(in.Token); err != nil {
		return nil, ErrInvalidToken
	}

	if err := s.cfg.Hooks.runBeforeAuthenticate(ctx, &in); err != nil {
		return nil, err
	}

	now := s.now()
	tokenHash := HashToken(in.Token)

	// 1. Try cache lookup
	var record *store.TokenRecord
	cachedRec, err := s.cache.GetByHash(ctx, tokenHash)
	if err == nil && cachedRec != nil {
		record = cachedRec
	}

	// 2. Cache miss -> query Store (source of truth)
	if record == nil {
		rec, err := s.store.GetByTokenHash(ctx, tokenHash)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil, ErrInvalidToken
			}
			return nil, err
		}
		record = rec

		// Populate cache if token is currently valid
		if record.Active(now) {
			remainingTTL := record.ExpiresAt.Sub(now)
			cacheTTL := s.cfg.CacheTTL
			if !record.ExpiresAt.IsZero() && remainingTTL < cacheTTL {
				cacheTTL = remainingTTL
			}
			_ = s.cache.Set(ctx, record, cacheTTL)
		}
	}

	// 3. Security checks: revocation and expiration
	if record.Revoked() {
		_ = s.cache.DeleteByHash(ctx, tokenHash)
		return nil, ErrTokenRevoked
	}

	if record.Expired(now) {
		_ = s.cache.DeleteByHash(ctx, tokenHash)
		s.publishEvent(ctx, EventBearerTokenExpired, record.Subject, TokenExpiredPayload{
			TokenID:   record.ID,
			Subject:   record.Subject,
			ExpiresAt: record.ExpiresAt,
			Time:      now,
		})
		return nil, ErrTokenExpired
	}

	// 4. Scope authorization checks
	if len(in.RequiredScopes) > 0 && !record.HasScopes(in.RequiredScopes...) {
		return nil, ErrInsufficientScope
	}

	info := recordToInfo(record)
	principal := info.Principal()
	result := &AuthResult{
		Principal: principal,
		Token:     info,
	}

	if err := s.cfg.Hooks.runAfterAuthenticate(ctx, result); err != nil {
		return nil, err
	}

	s.publishEvent(ctx, EventBearerAuthenticated, record.Subject, AuthenticatedPayload{
		TokenID:       record.ID,
		Subject:       record.Subject,
		PrincipalType: principal.Type,
		Time:          now,
	})

	return result, nil
}

// Issue generates and persists a new opaque bearer token.
func (s *service) Issue(ctx context.Context, in IssueInput) (*IssueResult, error) {
	if in.Subject == "" {
		return nil, ErrInvalidInput
	}

	if err := s.cfg.Hooks.runBeforeIssue(ctx, &in); err != nil {
		return nil, err
	}

	id, err := GenerateID()
	if err != nil {
		return nil, err
	}

	tokenPrefix := s.cfg.TokenPrefix
	rawToken, err := GenerateToken(tokenPrefix)
	if err != nil {
		return nil, err
	}

	tokenHash := HashToken(rawToken)
	now := s.now()

	ttl := in.TTL
	if ttl <= 0 {
		ttl = s.cfg.DefaultTTL
	}
	expiresAt := now.Add(ttl)

	pType := in.PrincipalType
	if pType == "" {
		pType = auth.PrincipalUser
	}

	record := &store.TokenRecord{
		ID:            id,
		TokenHash:     tokenHash,
		Subject:       in.Subject,
		PrincipalType: string(pType),
		Scopes:        in.Scopes,
		Metadata:      in.Metadata,
		ExpiresAt:     expiresAt,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	if err := s.store.Create(ctx, record); err != nil {
		return nil, err
	}

	// Cache acceleration
	cacheTTL := s.cfg.CacheTTL
	if ttl < cacheTTL {
		cacheTTL = ttl
	}
	_ = s.cache.Set(ctx, record, cacheTTL)

	info := recordToInfo(record)
	result := &IssueResult{
		Token: rawToken,
		Info:  info,
	}

	if err := s.cfg.Hooks.runAfterIssue(ctx, result); err != nil {
		return nil, err
	}

	s.publishEvent(ctx, EventBearerTokenIssued, record.Subject, TokenIssuedPayload{
		TokenID:       record.ID,
		Subject:       record.Subject,
		PrincipalType: pType,
		Scopes:        record.Scopes,
		ExpiresAt:     record.ExpiresAt,
		CreatedAt:     record.CreatedAt,
	})

	return result, nil
}

// Revoke invalidates an active token by its record ID.
func (s *service) Revoke(ctx context.Context, tokenID string) error {
	if tokenID == "" {
		return ErrInvalidInput
	}

	if err := s.cfg.Hooks.runBeforeRevoke(ctx, tokenID); err != nil {
		return err
	}

	now := s.now()
	// Invalidate cache first
	_ = s.cache.DeleteByID(ctx, tokenID)

	if err := s.store.Revoke(ctx, tokenID, now); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrTokenNotFound
		}
		return err
	}

	if err := s.cfg.Hooks.runAfterRevoke(ctx, tokenID); err != nil {
		return err
	}

	s.publishEvent(ctx, EventBearerTokenRevoked, tokenID, TokenRevokedPayload{
		TokenID:   tokenID,
		RevokedAt: now,
	})

	return nil
}

// RevokeBySubject revokes all active bearer tokens belonging to the specified subject.
func (s *service) RevokeBySubject(ctx context.Context, subject string) error {
	if subject == "" {
		return ErrInvalidInput
	}

	now := s.now()
	records, err := s.store.ListBySubject(ctx, subject)
	if err == nil {
		for _, rec := range records {
			_ = s.cache.DeleteByHash(ctx, rec.TokenHash)
			_ = s.cache.DeleteByID(ctx, rec.ID)
		}
	}

	if err := s.store.RevokeBySubject(ctx, subject, now); err != nil {
		return err
	}

	s.publishEvent(ctx, EventBearerTokenRevoked, subject, TokenRevokedPayload{
		Subject:   subject,
		RevokedAt: now,
	})

	return nil
}

// Get retrieves public metadata for a token by its record ID.
func (s *service) Get(ctx context.Context, tokenID string) (*TokenInfo, error) {
	if tokenID == "" {
		return nil, ErrInvalidInput
	}

	rec, err := s.store.GetByID(ctx, tokenID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrTokenNotFound
		}
		return nil, err
	}

	return recordToInfo(rec), nil
}

// ListBySubject lists public metadata for all tokens belonging to the subject.
func (s *service) ListBySubject(ctx context.Context, subject string) ([]*TokenInfo, error) {
	if subject == "" {
		return nil, ErrInvalidInput
	}

	records, err := s.store.ListBySubject(ctx, subject)
	if err != nil {
		return nil, err
	}

	infos := make([]*TokenInfo, 0, len(records))
	for _, rec := range records {
		infos = append(infos, recordToInfo(rec))
	}
	return infos, nil
}

// Delete permanently removes a token record by its ID.
func (s *service) Delete(ctx context.Context, tokenID string) error {
	if tokenID == "" {
		return ErrInvalidInput
	}

	_ = s.cache.DeleteByID(ctx, tokenID)

	if err := s.store.Delete(ctx, tokenID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrTokenNotFound
		}
		return err
	}
	return nil
}

// PurgeExpired permanently removes expired and revoked tokens from persistence.
func (s *service) PurgeExpired(ctx context.Context) (int, error) {
	return s.store.DeleteExpired(ctx, s.now())
}

func (s *service) publishEvent(ctx context.Context, name auth.EventName, subject string, payload any) {
	if s.host != nil && s.host.Events() != nil {
		s.host.Events().Publish(ctx, auth.Event{
			Name:    name,
			Time:    s.now(),
			Subject: subject,
			Payload: payload,
		})
	}
}

func recordToInfo(r *store.TokenRecord) *TokenInfo {
	if r == nil {
		return nil
	}
	return &TokenInfo{
		ID:            r.ID,
		Subject:       r.Subject,
		PrincipalType: auth.PrincipalType(r.PrincipalType),
		Scopes:        r.Scopes,
		Metadata:      r.Metadata,
		ExpiresAt:     r.ExpiresAt,
		RevokedAt:     r.RevokedAt,
		CreatedAt:     r.CreatedAt,
	}
}
