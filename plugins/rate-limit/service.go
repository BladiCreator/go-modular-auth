package ratelimit

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
)

type service struct {
	ctx      *sdk.Context
	engine   *limiterEngine
	logger   *slog.Logger
	mu       sync.RWMutex
	policies map[string]Policy
	failMode FailMode
}

var _ RateLimit = (*service)(nil)

func newService(ctx *sdk.Context, cfg Config) *service {
	var logger *slog.Logger
	if ctx != nil {
		logger = ctx.Logger()
	} else {
		logger = slog.Default()
	}

	var cacheAdapter = ctx.Cache()
	engine := newEngine(cacheAdapter, cfg.Clock)

	s := &service{
		ctx:      ctx,
		engine:   engine,
		logger:   logger,
		policies: make(map[string]Policy),
		failMode: cfg.DefaultFailMode,
	}

	for k, v := range cfg.Policies {
		s.policies[k] = v
	}

	return s
}

// Check evaluates whether a request exceeds the limit without consuming tokens.
func (s *service) Check(ctx context.Context, req Request) (*Decision, error) {
	if req.Action == "" {
		return nil, ErrActionRequired
	}

	policy, ok := s.getPolicy(req.Action)
	if !ok {
		// No rate limit configured for this action: allow freely
		return &Decision{
			Allowed:   true,
			Remaining: 999999,
			Limit:     999999,
			Action:    req.Action,
		}, nil
	}

	key := policy.BuildKey(req)
	return s.engine.evaluate(ctx, key, policy, false)
}

// Allow evaluates and consumes one token if within limits, returning the decision.
func (s *service) Allow(ctx context.Context, req Request) (*Decision, error) {
	if req.Action == "" {
		return nil, ErrActionRequired
	}

	policy, ok := s.getPolicy(req.Action)
	if !ok {
		return &Decision{
			Allowed:   true,
			Remaining: 999999,
			Limit:     999999,
			Action:    req.Action,
		}, nil
	}

	key := policy.BuildKey(req)
	decision, err := s.engine.evaluate(ctx, key, policy, true)
	if err != nil {
		s.logger.WarnContext(ctx, "ratelimit: evaluation failed",
			"action", req.Action,
			"key", key,
			"error", err,
		)
		return nil, err
	}

	if !decision.Allowed {
		s.logger.InfoContext(ctx, "ratelimit: request throttled",
			"action", req.Action,
			"key", key,
			"retry_after", decision.RetryAfter,
		)
		if s.ctx != nil && s.ctx.Events() != nil {
			s.ctx.Events().Publish(ctx, auth.Event{
				Name:    EventRateLimitExceeded,
				Time:    time.Now().UTC(),
				Subject: req.Identity,
				Payload: ExceededPayload{
					Action:     req.Action,
					Key:        key,
					RetryAfter: decision.RetryAfter,
					OccurredAt: time.Now().UTC(),
				},
			})
		}
	}

	return decision, nil
}

// Require checks and consumes a token, returning ErrRateLimitExceeded if throttled.
func (s *service) Require(ctx context.Context, req Request) error {
	decision, err := s.Allow(ctx, req)
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return ErrRateLimitExceeded
	}
	return nil
}

// Reset clears active rate limit counters for a given request target.
func (s *service) Reset(ctx context.Context, req Request) error {
	if req.Action == "" {
		return ErrActionRequired
	}

	policy, ok := s.getPolicy(req.Action)
	if !ok {
		return nil
	}

	key := policy.BuildKey(req)
	return s.engine.reset(ctx, key, policy.Window)
}

// Policy retrieves the currently configured policy for an action.
func (s *service) Policy(action string) (Policy, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.policies[action]
	return p, ok
}

// SetPolicy registers or dynamically overrides the policy for an action.
func (s *service) SetPolicy(policy Policy) error {
	if policy.Action == "" {
		return ErrActionRequired
	}
	if policy.Algorithm == AlgorithmTokenBucket {
		if policy.Capacity <= 0 || policy.RefillRate <= 0 {
			return fmt.Errorf("%w: capacity and refill_rate must be positive", ErrInvalidPolicy)
		}
	} else {
		if policy.Limit <= 0 || policy.Window <= 0 {
			return fmt.Errorf("%w: limit and window must be positive", ErrInvalidPolicy)
		}
	}

	if policy.FailMode == "" {
		policy.FailMode = s.failMode
	}

	s.mu.Lock()
	s.policies[policy.Action] = policy
	s.mu.Unlock()

	return nil
}

func (s *service) getPolicy(action string) (Policy, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.policies[action]
	return p, ok
}
