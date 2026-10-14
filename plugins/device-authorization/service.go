package deviceauth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth/adapter"
	"github.com/BladiCreator/go-modular-auth-device-authorization/cache"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
	"github.com/BladiCreator/go-modular-auth/session"
)

type service struct {
	ctx         *sdk.Context
	cfg         Config
	rateLimiter cache.RateLimiter
}

var _ DeviceAuthorization = (*service)(nil)

func newService(ctx *sdk.Context, cfg Config) *service {
	var c cache.RateLimiter
	if ctx != nil && ctx.Cache() != nil {
		c = cache.NewRateLimiter(ctx.Cache())
	} else {
		c = cache.NewRateLimiter(nil)
	}

	return &service{
		ctx:         ctx,
		cfg:         cfg,
		rateLimiter: c,
	}
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

// Start initiates the device authorization grant workflow (RFC 8628 section 3.1 & 3.2).
func (s *service) Start(ctx context.Context, in DeviceAuthorizationRequestInput) (*DeviceAuthorizationResponse, error) {
	if strings.TrimSpace(in.ClientID) == "" {
		return nil, fmt.Errorf("%w: client_id is required", ErrInvalidInput)
	}

	var deviceCode, deviceCodeHash, userCode string
	var err error

	// Retry loop in case of rare collision on user_code
	for attempts := 0; attempts < 3; attempts++ {
		deviceCode, deviceCodeHash, err = generateDeviceCode()
		if err != nil {
			return nil, err
		}
		userCode, err = generateUserCode()
		if err != nil {
			return nil, err
		}

		now := s.now()
		expiresAt := now.Add(s.cfg.ExpiresIn)
		intervalSeconds := int(s.cfg.PollingInterval.Seconds())
		if intervalSeconds <= 0 {
			intervalSeconds = 5
		}

		grant := &DeviceGrant{
			ID:              generateID(),
			ClientID:        in.ClientID,
			DeviceCodeHash:  deviceCodeHash,
			UserCode:        userCode,
			Status:          StatusPending,
			Scope:           in.Scope,
			Metadata:        in.Metadata,
			ExpiresAt:       expiresAt,
			PollingInterval: intervalSeconds,
			CreatedAt:       now,
			UpdatedAt:       now,
		}

		repo := sdk.Model[DeviceGrant](s.ctx, ModelDeviceGrants)
		err = repo.Create(ctx, grant)
		if err == nil {
			break
		}
		if !errors.Is(err, adapter.ErrConflict) {
			return nil, err
		}
	}
	if err != nil {
		return nil, fmt.Errorf("device auth: failed to allocate unique user code: %w", err)
	}

	completeURI := s.cfg.VerificationURIComplete
	if completeURI == "" && s.cfg.VerificationURI != "" {
		sep := "?"
		if strings.Contains(s.cfg.VerificationURI, "?") {
			sep = "&"
		}
		completeURI = s.cfg.VerificationURI + sep + "user_code=" + userCode
	}

	s.publish(ctx, EventDeviceAuthStarted, in.ClientID, DeviceAuthStartedPayload{
		GrantID:         deviceCodeHash[:12],
		ClientID:        in.ClientID,
		UserCode:        userCode,
		ExpiresAt:       s.now().Add(s.cfg.ExpiresIn),
		PollingInterval: int(s.cfg.PollingInterval.Seconds()),
		CreatedAt:       s.now(),
	})

	return &DeviceAuthorizationResponse{
		DeviceCode:              deviceCode,
		UserCode:                userCode,
		VerificationURI:         s.cfg.VerificationURI,
		VerificationURIComplete: completeURI,
		ExpiresIn:               int(s.cfg.ExpiresIn.Seconds()),
		Interval:                int(s.cfg.PollingInterval.Seconds()),
	}, nil
}

// Poll checks device authorization status and issues tokens upon user approval.
func (s *service) Poll(ctx context.Context, in PollInput) (*PollResponse, error) {
	if in.DeviceCode == "" || in.ClientID == "" {
		return nil, ErrInvalidInput
	}

	codeHash := hashDeviceCode(in.DeviceCode)
	now := s.now()

	var grant *DeviceGrant
	var sessionResult *auth.IssuedSession
	var statusErr error

	err := s.ctx.Adapter().Transaction(ctx, func(txCtx context.Context, tx adapter.Adapter) error {
		repo := sdk.FromAdapter[DeviceGrant](tx, ModelDeviceGrants)
		var err error
		grant, err = repo.FindOne(txCtx, adapter.Eq("device_code_hash", codeHash))
		if err != nil {
			if errors.Is(err, adapter.ErrNotFound) {
				return ErrInvalidGrant
			}
			return err
		}

		// Verify client binding
		if grant.ClientID != in.ClientID {
			return ErrInvalidGrant
		}

		// Check expiration
		if grant.Expired(now) {
			return ErrExpiredToken
		}

		switch grant.Status {
		case StatusConsumed:
			// Replay prevention: consumed grant cannot be reused
			return ErrInvalidGrant

		case StatusDenied:
			return ErrAccessDenied

		case StatusPending:
			// Check polling frequency for slow_down
			if grant.LastPolledAt != nil {
				elapsed := now.Sub(*grant.LastPolledAt)
				minInterval := time.Duration(grant.PollingInterval) * time.Second
				if elapsed < minInterval {
					// Slow down required by RFC 8628 section 3.5
					grant.PollingInterval += int(s.cfg.SlowDownIncrement.Seconds())
					grant.LastPolledAt = &now
					grant.UpdatedAt = now
					_, _ = repo.Update(txCtx, []adapter.Condition{adapter.Eq("id", grant.ID)}, map[string]any{
						"polling_interval": grant.PollingInterval,
						"last_polled_at":   grant.LastPolledAt,
						"updated_at":       grant.UpdatedAt,
					})
					statusErr = ErrSlowDown
					return nil // Commit polling interval increment!
				}
			}

			grant.LastPolledAt = &now
			grant.UpdatedAt = now
			_, _ = repo.Update(txCtx, []adapter.Condition{adapter.Eq("id", grant.ID)}, map[string]any{
				"last_polled_at": grant.LastPolledAt,
				"updated_at":     grant.UpdatedAt,
			})
			statusErr = ErrAuthorizationPending
			return nil // Commit LastPolledAt!

		case StatusAuthorized:
			// Single-use atomic fulfillment
			grant.Status = StatusConsumed
			grant.ConsumedAt = &now
			grant.UpdatedAt = now
			if _, err := repo.Update(txCtx, []adapter.Condition{adapter.Eq("id", grant.ID)}, map[string]any{
				"status":      grant.Status,
				"consumed_at": grant.ConsumedAt,
				"updated_at":  grant.UpdatedAt,
			}); err != nil {
				return err
			}

			// Issue session
			if s.ctx != nil && s.ctx.Core() != nil {
				sessionResult, err = s.ctx.Core().CreateSession(txCtx, grant.UserID, in.Session)
				if err != nil {
					return err
				}
			} else {
				// Standalone/mock fallback
				token, tokenHash := generateSessionToken()
				sess := &session.Session{
					ID:        generateID(),
					UserID:    grant.UserID,
					TokenHash: tokenHash,
					CreatedAt: now,
					ExpiresAt: now.Add(24 * time.Hour),
				}
				if s.ctx != nil && s.ctx.Store() != nil {
					_ = s.ctx.Store().Sessions().Create(txCtx, sess)
				}
				sessionResult = &auth.IssuedSession{
					Session: sess,
					Token:   token,
				}
			}
			return nil

		default:
			return ErrInvalidGrant
		}
	})
	if err != nil {
		return nil, err
	}
	if statusErr != nil {
		return nil, statusErr
	}

	s.publish(ctx, EventDeviceAuthConsumed, grant.UserID, DeviceAuthConsumedPayload{
		GrantID:    grant.ID,
		ClientID:   grant.ClientID,
		UserID:     grant.UserID,
		ConsumedAt: now,
	})

	return &PollResponse{
		Status:  StatusConsumed,
		UserID:  grant.UserID,
		Session: sessionResult.Session,
		Token:   sessionResult.Token,
	}, nil
}

// VerifyUserCode inspects a user code submitted by the user on the verification page.
func (s *service) VerifyUserCode(ctx context.Context, in VerifyUserCodeInput) (*UserCodeVerificationResult, error) {
	cleanCode := normalizeUserCode(in.UserCode)
	if cleanCode == "" {
		return nil, ErrInvalidUserCode
	}

	// Apply rate limiting per IP if provided
	if in.ClientIP != "" && s.rateLimiter != nil {
		allowed, err := s.rateLimiter.Allow(ctx, "verify:"+in.ClientIP, s.cfg.RateLimitPerMinute, 1*time.Minute)
		if err != nil {
			return nil, err
		}
		if !allowed {
			return nil, ErrRateLimited
		}
	}

	repo := sdk.Model[DeviceGrant](s.ctx, ModelDeviceGrants)
	grant, err := repo.FindOne(ctx, adapter.Eq("user_code", cleanCode))
	if err != nil {
		if errors.Is(err, adapter.ErrNotFound) {
			return nil, ErrInvalidUserCode
		}
		return nil, err
	}

	if grant.FailedAttempts >= s.cfg.MaxFailedAttempts {
		return nil, ErrMaxAttemptsExceeded
	}

	now := s.now()
	if grant.Expired(now) {
		return nil, ErrExpiredToken
	}

	switch grant.Status {
	case StatusConsumed:
		return nil, ErrAlreadyConsumed
	case StatusDenied:
		return nil, ErrAlreadyDenied
	case StatusAuthorized:
		return nil, ErrAlreadyAuthorized
	}

	return &UserCodeVerificationResult{
		GrantID:   grant.ID,
		ClientID:  grant.ClientID,
		UserCode:  grant.UserCode,
		Scope:     grant.Scope,
		Metadata:  grant.Metadata,
		ExpiresAt: grant.ExpiresAt,
	}, nil
}

// Authorize records user consent and associates the grant with the authorizing user.
func (s *service) Authorize(ctx context.Context, in AuthorizeInput) error {
	cleanCode := normalizeUserCode(in.UserCode)
	if cleanCode == "" || in.Principal.Subject == "" {
		return ErrInvalidInput
	}

	now := s.now()
	var grant *DeviceGrant

	err := s.ctx.Adapter().Transaction(ctx, func(txCtx context.Context, tx adapter.Adapter) error {
		repo := sdk.FromAdapter[DeviceGrant](tx, ModelDeviceGrants)
		var err error
		grant, err = repo.FindOne(txCtx, adapter.Eq("user_code", cleanCode))
		if err != nil {
			if errors.Is(err, adapter.ErrNotFound) {
				return ErrInvalidUserCode
			}
			return err
		}

		if grant.FailedAttempts >= s.cfg.MaxFailedAttempts {
			return ErrMaxAttemptsExceeded
		}

		if grant.Expired(now) {
			return ErrExpiredToken
		}

		switch grant.Status {
		case StatusAuthorized:
			return ErrAlreadyAuthorized
		case StatusDenied:
			return ErrAlreadyDenied
		case StatusConsumed:
			return ErrAlreadyConsumed
		}

		grant.Status = StatusAuthorized
		grant.UserID = in.Principal.Subject
		if in.Scope != "" {
			grant.Scope = in.Scope
		}
		grant.AuthorizedAt = &now
		grant.UpdatedAt = now

		_, err = repo.Update(txCtx, []adapter.Condition{adapter.Eq("id", grant.ID)}, map[string]any{
			"status":        grant.Status,
			"user_id":       grant.UserID,
			"scope":         grant.Scope,
			"authorized_at": grant.AuthorizedAt,
			"updated_at":    grant.UpdatedAt,
		})
		return err
	})
	if err != nil {
		return err
	}

	s.publish(ctx, EventDeviceAuthAuthorized, in.Principal.Subject, DeviceAuthAuthorizedPayload{
		GrantID:      grant.ID,
		ClientID:     grant.ClientID,
		UserCode:     cleanCode,
		UserID:       in.Principal.Subject,
		AuthorizedAt: now,
	})

	return nil
}

// Deny records user rejection of the authorization request.
func (s *service) Deny(ctx context.Context, in DenyInput) error {
	cleanCode := normalizeUserCode(in.UserCode)
	if cleanCode == "" {
		return ErrInvalidInput
	}

	now := s.now()
	var grant *DeviceGrant

	err := s.ctx.Adapter().Transaction(ctx, func(txCtx context.Context, tx adapter.Adapter) error {
		repo := sdk.FromAdapter[DeviceGrant](tx, ModelDeviceGrants)
		var err error
		grant, err = repo.FindOne(txCtx, adapter.Eq("user_code", cleanCode))
		if err != nil {
			if errors.Is(err, adapter.ErrNotFound) {
				return ErrInvalidUserCode
			}
			return err
		}

		if grant.Expired(now) {
			return ErrExpiredToken
		}

		switch grant.Status {
		case StatusAuthorized:
			return ErrAlreadyAuthorized
		case StatusDenied:
			return ErrAlreadyDenied
		case StatusConsumed:
			return ErrAlreadyConsumed
		}

		grant.Status = StatusDenied
		grant.UpdatedAt = now

		_, err = repo.Update(txCtx, []adapter.Condition{adapter.Eq("id", grant.ID)}, map[string]any{
			"status":     grant.Status,
			"updated_at": grant.UpdatedAt,
		})
		return err
	})
	if err != nil {
		return err
	}

	s.publish(ctx, EventDeviceAuthDenied, in.Principal.Subject, DeviceAuthDeniedPayload{
		GrantID:  grant.ID,
		ClientID: grant.ClientID,
		UserCode: cleanCode,
		DeniedAt: now,
	})

	return nil
}
