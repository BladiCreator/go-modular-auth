package jwt

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"slices"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth/adapter"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
	jwtcache "github.com/BladiCreator/go-modular-auth/plugins/jwt/cache"
)

type service struct {
	ctx   *sdk.Context
	cfg   Config
	km    KeyManager
	cache jwtcache.RevocationCache
	hooks *Hooks
}

var _ JWT = (*service)(nil)

func newService(ctx *sdk.Context, cfg Config) *service {
	s := &service{
		ctx:   ctx,
		cfg:   cfg,
		km:    cfg.KeyManager,
		cache: cfg.Cache,
		hooks: cfg.Hooks,
	}

	// Auto-wire store/cache from host if not explicitly configured in Config
	if s.cache == nil && ctx != nil && ctx.Cache() != nil {
		s.cache = jwtcache.New(ctx.Cache())
	}

	return s
}

func (s *service) now() time.Time {
	if s.ctx != nil {
		return s.ctx.Now()
	}
	return time.Now()
}

func (s *service) publish(ctx context.Context, name auth.EventName, subject string, payload any) {
	if s.ctx != nil && s.ctx.Events() != nil {
		s.ctx.Events().Publish(ctx, auth.Event{
			Name:    name,
			Time:    s.now(),
			Subject: subject,
			Payload: payload,
		})
	}
}

func (s *service) Keys() KeyManager {
	return s.km
}

func (s *service) Issue(ctx context.Context, claims Claims) (string, error) {
	key, err := s.km.GetActiveSigningKey()
	if err != nil {
		return "", err
	}
	return s.IssueWithKey(ctx, key.ID, claims)
}

func (s *service) IssueWithKey(ctx context.Context, keyID string, claims Claims) (string, error) {
	key, err := s.km.GetKey(keyID)
	if err != nil {
		return "", err
	}
	if !key.CanSign() {
		return "", ErrNoActiveSigningKey
	}

	now := s.now()

	// Apply configured defaults
	if claims.Issuer == "" && s.cfg.Issuer != "" {
		claims.Issuer = s.cfg.Issuer
	}
	if len(claims.Audience) == 0 && len(s.cfg.DefaultAudience) > 0 {
		claims.Audience = s.cfg.DefaultAudience
	}
	if claims.IssuedAt == nil || claims.IssuedAt.IsZero() {
		claims.IssuedAt = NewNumericDate(now)
	}
	if claims.ExpiresAt == nil || claims.ExpiresAt.IsZero() {
		claims.ExpiresAt = NewNumericDate(claims.IssuedAt.Add(s.cfg.DefaultTTL))
	}
	if claims.ID == "" {
		claims.ID = generateJTI()
	}

	if err := s.hooks.runBeforeIssue(ctx, &claims); err != nil {
		return "", err
	}

	header := tokenHeader{
		Alg: string(key.Algorithm),
		Typ: "JWT",
		Kid: key.ID,
	}

	tokenString, err := encodeToken(header, claims, key)
	if err != nil {
		return "", err
	}

	if err := s.hooks.runAfterIssue(ctx, tokenString, &claims); err != nil {
		return "", err
	}

	s.publish(ctx, EventJWTTokenIssued, claims.Subject, TokenIssuedPayload{
		KeyID:     key.ID,
		JTI:       claims.ID,
		Subject:   claims.Subject,
		Issuer:    claims.Issuer,
		Audience:  claims.Audience,
		ExpiresAt: claims.ExpiresAt.Time,
		IssuedAt:  claims.IssuedAt.Time,
	})

	return tokenString, nil
}

func (s *service) Verify(ctx context.Context, tokenString string, opts ...VerifyOption) (*Claims, error) {
	if err := s.hooks.runBeforeVerify(ctx, tokenString); err != nil {
		return nil, err
	}

	parsed, err := parseToken(tokenString)
	if err != nil {
		return nil, err
	}

	alg := Algorithm(parsed.header.Alg)

	// Enforce algorithm whitelist
	if !slices.Contains(s.cfg.AllowedAlgorithms, alg) {
		return nil, ErrAlgorithmNotAllowed
	}

	// Retrieve verification key and strictly enforce algorithm agreement
	key, err := s.km.GetVerificationKey(parsed.header.Kid, alg)
	if err != nil {
		return nil, err
	}

	// Cryptographic signature verification
	if err := verifySignature(key.Algorithm, key.PublicKey, parsed.signingInput, parsed.signature); err != nil {
		return nil, err
	}

	// Standard claims validation (exp, nbf, iss, aud, sub, required claims)
	vCfg := verifyConfig{
		leeway: s.cfg.Leeway,
	}
	for _, opt := range opts {
		opt(&vCfg)
	}

	if err := parsed.claims.Validate(s.now(), &vCfg); err != nil {
		return nil, err
	}

	// Check revocation if store/cache is configured
	var issuedAt time.Time
	if parsed.claims.IssuedAt != nil {
		issuedAt = parsed.claims.IssuedAt.Time
	}
	revoked, err := s.IsRevoked(ctx, parsed.claims.ID, parsed.claims.Subject, issuedAt)
	if err != nil {
		return nil, err
	}
	if revoked {
		return nil, ErrTokenRevoked
	}

	if err := s.hooks.runAfterVerify(ctx, &parsed.claims); err != nil {
		return nil, err
	}

	s.publish(ctx, EventJWTTokenVerified, parsed.claims.Subject, TokenVerifiedPayload{
		KeyID:   key.ID,
		JTI:     parsed.claims.ID,
		Subject: parsed.claims.Subject,
		Issuer:  parsed.claims.Issuer,
		Time:    s.now(),
	})

	return &parsed.claims, nil
}

func (s *service) Revoke(ctx context.Context, jti string, expiresAt time.Time, reason string) error {
	if jti == "" {
		return nil
	}
	if err := s.hooks.runBeforeRevoke(ctx, jti); err != nil {
		return err
	}

	now := s.now()
	if expiresAt.IsZero() {
		expiresAt = now.Add(s.cfg.DefaultTTL)
	}

	if s.ctx != nil && s.ctx.Adapter() != nil {
		rec := &RevocationRecord{
			JTI:       jti,
			Reason:    reason,
			ExpiresAt: expiresAt,
			RevokedAt: now,
		}
		repo := sdk.Model[RevocationRecord](s.ctx, ModelJWTRevocations)
		if err := repo.Create(ctx, rec); err != nil {
			if errors.Is(err, adapter.ErrConflict) {
				_, _ = repo.Update(ctx, []adapter.Condition{adapter.Eq("jti", jti)}, map[string]any{
					"reason":     reason,
					"expires_at": expiresAt,
					"revoked_at": now,
				})
			} else {
				return err
			}
		}
	}

	if s.cache != nil {
		ttl := time.Until(expiresAt)
		if ttl > 0 {
			_ = s.cache.SetTokenRevoked(ctx, jti, ttl)
		}
	}

	if err := s.hooks.runAfterRevoke(ctx, jti); err != nil {
		return err
	}

	s.publish(ctx, EventJWTTokenRevoked, "", TokenRevokedPayload{
		JTI:       jti,
		Reason:    reason,
		RevokedAt: now,
	})

	return nil
}

func (s *service) RevokeSubject(ctx context.Context, subject string, cutoff time.Time, reason string) error {
	if subject == "" {
		return nil
	}
	now := s.now()
	if cutoff.IsZero() {
		cutoff = now
	}

	if s.ctx != nil && s.ctx.Adapter() != nil {
		repo := sdk.Model[SubjectRevocationRecord](s.ctx, ModelJWTSubjectRevocations)
		existing, err := repo.FindOne(ctx, adapter.Eq("subject", subject))
		if err == nil && existing != nil {
			if existing.Cutoff.After(cutoff) {
				// Keep the later cutoff
			} else {
				_, err := repo.Update(ctx, []adapter.Condition{adapter.Eq("subject", subject)}, map[string]any{
					"cutoff":     cutoff,
					"reason":     reason,
					"revoked_at": now,
				})
				if err != nil {
					return err
				}
			}
		} else {
			rec := &SubjectRevocationRecord{
				Subject:   subject,
				Cutoff:    cutoff,
				Reason:    reason,
				RevokedAt: now,
			}
			if err := repo.Create(ctx, rec); err != nil {
				return err
			}
		}
	}

	if s.cache != nil {
		_ = s.cache.SetSubjectCutoff(ctx, subject, cutoff, s.cfg.DefaultTTL)
	}

	s.publish(ctx, EventJWTTokenRevoked, subject, TokenRevokedPayload{
		Subject:   subject,
		Reason:    reason,
		RevokedAt: now,
	})

	return nil
}

func (s *service) IsRevoked(ctx context.Context, jti string, subject string, issuedAt time.Time) (bool, error) {
	now := s.now()
	// 1. Check individual token revocation (JTI)
	if jti != "" {
		if s.cache != nil {
			if revoked, found := s.cache.IsTokenRevoked(ctx, jti); found {
				if revoked {
					return true, nil
				}
			}
		}
		if s.ctx != nil && s.ctx.Adapter() != nil {
			repo := sdk.Model[RevocationRecord](s.ctx, ModelJWTRevocations)
			rec, err := repo.FindOne(ctx, adapter.Eq("jti", jti))
			if err != nil && !errors.Is(err, adapter.ErrNotFound) {
				return false, err
			}
			if rec != nil {
				if !rec.ExpiresAt.IsZero() && now.After(rec.ExpiresAt) {
					// Expired record
				} else {
					if s.cache != nil {
						_ = s.cache.SetTokenRevoked(ctx, jti, s.cfg.DefaultTTL)
					}
					return true, nil
				}
			}
		}
	}

	// 2. Check subject-wide cutoff revocation
	if subject != "" && !issuedAt.IsZero() {
		if s.cache != nil {
			if cutoff, found := s.cache.GetSubjectCutoff(ctx, subject); found {
				if !issuedAt.After(cutoff) {
					return true, nil
				}
			}
		}
		if s.ctx != nil && s.ctx.Adapter() != nil {
			repo := sdk.Model[SubjectRevocationRecord](s.ctx, ModelJWTSubjectRevocations)
			rec, err := repo.FindOne(ctx, adapter.Eq("subject", subject))
			if err != nil && !errors.Is(err, adapter.ErrNotFound) {
				return false, err
			}
			if rec != nil {
				if !issuedAt.After(rec.Cutoff) {
					return true, nil
				}
			}
		}
	}

	return false, nil
}

func (s *service) JWKS(ctx context.Context) (*JWKS, error) {
	return BuildJWKS(s.km)
}

func generateJTI() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
