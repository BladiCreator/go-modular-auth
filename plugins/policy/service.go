package policy

import (
	"context"
	"fmt"
	"sync"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth/adapter"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
	"github.com/BladiCreator/go-modular-auth/plugins/policy/cache"
)

type service struct {
	ctx   *sdk.Context
	cache cache.Cache
	cfg   Config

	mu          sync.RWMutex
	policies    map[string]Evaluator
	policyOrder []string
}

var _ Policy = (*service)(nil)

func newService(ctx *sdk.Context, cfg Config) *service {
	var c cache.Cache = cfg.Cache
	if c == nil && ctx != nil && ctx.Cache() != nil {
		c = cache.NewCoreCacheAdapter(ctx.Cache(), cfg.CacheTTL)
	}

	s := &service{
		ctx:         ctx,
		cache:       c,
		cfg:         cfg,
		policies:    make(map[string]Evaluator),
		policyOrder: make([]string, 0),
	}

	for _, p := range cfg.InitialPolicies {
		_ = s.RegisterPolicy(p)
	}

	return s
}

func (s *service) Authorize(ctx context.Context, req Request) error {
	d, err := s.Evaluate(ctx, req)
	if err != nil {
		return err
	}
	if d.IsAllowed() {
		return nil
	}
	if d.IsChallenge() {
		return ErrChallengeRequired
	}
	return ErrForbidden
}

func (s *service) Evaluate(ctx context.Context, req Request) (Decision, error) {
	if req.Resource.Type == "" || req.Action == "" {
		return Decision{}, ErrInvalidRequest
	}

	cacheKey := cache.BuildKey(
		req.Principal.Subject,
		string(req.Principal.Type),
		req.Organization,
		req.Resource.Type,
		req.Resource.ID,
		req.Action,
	)

	if s.cache != nil {
		if cached, hit, err := s.cache.GetDecision(ctx, cacheKey); err == nil && hit && cached != nil {
			var ch *ChallengeInfo
			if cached.Challenge != nil {
				ch = &ChallengeInfo{
					Type:    fmt.Sprintf("%v", cached.Challenge["type"]),
					Message: fmt.Sprintf("%v", cached.Challenge["message"]),
				}
				if dt, ok := cached.Challenge["details"].(map[string]any); ok {
					ch.Details = dt
				}
			}
			return Decision{
				Effect:      Effect(cached.Effect),
				Reason:      cached.Reason,
				Challenge:   ch,
				PolicyID:    cached.PolicyID,
				EvaluatedAt: cached.CachedAt,
			}, nil
		}
	}

	s.mu.RLock()
	activeList := make([]Evaluator, 0, len(s.policyOrder))
	for _, id := range s.policyOrder {
		if p, ok := s.policies[id]; ok {
			activeList = append(activeList, p)
		}
	}
	s.mu.RUnlock()

	var decision Decision
	var err error

	if len(activeList) == 0 {
		decision = Deny("core:default", "no active policies registered; deny by default")
	} else {
		switch s.cfg.Combinator {
		case CombinatorAllOf:
			decision, err = s.evalAllOf(ctx, req, activeList)
		case CombinatorAnyOf:
			decision, err = s.evalAnyOf(ctx, req, activeList)
		case CombinatorDenyOverrides:
			fallthrough
		default:
			decision, err = s.evalDenyOverrides(ctx, req, activeList)
		}
	}

	if err != nil {
		return Decision{}, err
	}

	decision.EvaluatedAt = s.cfg.Clock()

	if s.cache != nil {
		var chMap map[string]any
		if decision.Challenge != nil {
			chMap = map[string]any{
				"type":    decision.Challenge.Type,
				"message": decision.Challenge.Message,
				"details": decision.Challenge.Details,
			}
		}
		_ = s.cache.SetDecision(ctx, cacheKey, &cache.CachedDecision{
			Effect:    string(decision.Effect),
			Reason:    decision.Reason,
			Challenge: chMap,
			PolicyID:  decision.PolicyID,
			CachedAt:  decision.EvaluatedAt,
		}, s.cfg.CacheTTL)
	}

	if s.ctx != nil && s.ctx.Events() != nil {
		s.ctx.Events().Publish(ctx, auth.Event{
			Name:    EventPolicyEvaluated,
			Time:    decision.EvaluatedAt,
			Subject: req.Principal.Subject,
			Payload: PolicyEvaluatedPayload{
				PrincipalSubject: req.Principal.Subject,
				PrincipalType:    string(req.Principal.Type),
				Organization:     req.Organization,
				ResourceType:     req.Resource.Type,
				ResourceID:       req.Resource.ID,
				Action:           req.Action,
				Effect:           decision.Effect,
				Reason:           decision.Reason,
				PolicyID:         decision.PolicyID,
				Timestamp:        decision.EvaluatedAt,
			},
		})
	}

	return decision, nil
}

func (s *service) evalDenyOverrides(ctx context.Context, req Request, list []Evaluator) (Decision, error) {
	var allowed bool
	var matchedAllowID string
	var pendingChallenge *Decision

	for _, e := range list {
		d, err := e.Evaluate(ctx, req)
		if err != nil {
			return Decision{}, fmt.Errorf("evaluating policy %q: %w", e.ID(), err)
		}
		if d.IsDenied() {
			return Deny(e.ID(), fmt.Sprintf("denied by policy %q: %s", e.ID(), d.Reason)), nil
		}
		if d.IsChallenge() && pendingChallenge == nil {
			pendingChallenge = &d
		}
		if d.IsAllowed() {
			allowed = true
			matchedAllowID = e.ID()
		}
	}

	if pendingChallenge != nil {
		return *pendingChallenge, nil
	}

	if allowed {
		return Allow(matchedAllowID, "access granted under deny-overrides"), nil
	}

	return Deny("core:default", "no policy granted access under deny-overrides"), nil
}

func (s *service) evalAllOf(ctx context.Context, req Request, list []Evaluator) (Decision, error) {
	var pendingChallenge *Decision

	for _, e := range list {
		d, err := e.Evaluate(ctx, req)
		if err != nil {
			return Decision{}, fmt.Errorf("evaluating policy %q: %w", e.ID(), err)
		}
		if d.IsDenied() {
			return Deny(e.ID(), fmt.Sprintf("denied by policy %q: %s", e.ID(), d.Reason)), nil
		}
		if d.IsChallenge() && pendingChallenge == nil {
			pendingChallenge = &d
		}
	}

	if pendingChallenge != nil {
		return *pendingChallenge, nil
	}

	return Allow("composite:all_of", "all policies satisfied"), nil
}

func (s *service) evalAnyOf(ctx context.Context, req Request, list []Evaluator) (Decision, error) {
	var pendingChallenge *Decision

	for _, e := range list {
		d, err := e.Evaluate(ctx, req)
		if err != nil {
			return Decision{}, fmt.Errorf("evaluating policy %q: %w", e.ID(), err)
		}
		if d.IsAllowed() {
			return Allow(e.ID(), fmt.Sprintf("granted by policy %q", e.ID())), nil
		}
		if d.IsChallenge() && pendingChallenge == nil {
			pendingChallenge = &d
		}
	}

	if pendingChallenge != nil {
		return *pendingChallenge, nil
	}

	return Deny("composite:any_of", "no policy in AnyOf granted access"), nil
}

func (s *service) RegisterPolicy(p Evaluator) error {
	if p == nil || p.ID() == "" {
		return ErrInvalidRequest
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.policies[p.ID()]; exists {
		return ErrPolicyAlreadyExists
	}

	s.policies[p.ID()] = p
	s.policyOrder = append(s.policyOrder, p.ID())

	if s.ctx != nil && s.ctx.Adapter() != nil {
		now := s.cfg.Clock()
		_ = sdk.Model[PolicyRecord](s.ctx, ModelPolicies).Create(context.Background(), &PolicyRecord{
			ID:          p.ID(),
			Description: p.Description(),
			Combinator:  string(s.cfg.Combinator),
			CreatedAt:   now,
			UpdatedAt:   now,
		})
	}

	if s.cache != nil {
		_ = s.cache.InvalidateAll(context.Background())
	}

	if s.ctx != nil && s.ctx.Events() != nil {
		s.ctx.Events().Publish(context.Background(), auth.Event{
			Name:    EventPolicyRegistered,
			Time:    s.cfg.Clock(),
			Subject: p.ID(),
			Payload: PolicyRegisteredPayload{
				PolicyID:    p.ID(),
				Description: p.Description(),
				Timestamp:   s.cfg.Clock(),
			},
		})
	}

	return nil
}

func (s *service) RemovePolicy(policyID string) error {
	if policyID == "" {
		return ErrInvalidRequest
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.policies[policyID]; !exists {
		return ErrPolicyNotFound
	}

	delete(s.policies, policyID)

	newOrder := make([]string, 0, len(s.policyOrder)-1)
	for _, id := range s.policyOrder {
		if id != policyID {
			newOrder = append(newOrder, id)
		}
	}
	s.policyOrder = newOrder

	if s.ctx != nil && s.ctx.Adapter() != nil {
		_, _ = sdk.Model[PolicyRecord](s.ctx, ModelPolicies).Delete(context.Background(), adapter.Eq("id", policyID))
	}

	if s.cache != nil {
		_ = s.cache.InvalidateAll(context.Background())
	}

	if s.ctx != nil && s.ctx.Events() != nil {
		s.ctx.Events().Publish(context.Background(), auth.Event{
			Name:    EventPolicyRemoved,
			Time:    s.cfg.Clock(),
			Subject: policyID,
			Payload: PolicyRemovedPayload{
				PolicyID:  policyID,
				Timestamp: s.cfg.Clock(),
			},
		})
	}

	return nil
}

func (s *service) GetPolicy(policyID string) (Evaluator, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	p, exists := s.policies[policyID]
	if !exists {
		return nil, ErrPolicyNotFound
	}
	return p, nil
}

func (s *service) ListPolicies() []Evaluator {
	s.mu.RLock()
	defer s.mu.RUnlock()

	res := make([]Evaluator, 0, len(s.policyOrder))
	for _, id := range s.policyOrder {
		if p, exists := s.policies[id]; exists {
			res = append(res, p)
		}
	}
	return res
}

func (s *service) InvalidatePrincipalCache(ctx context.Context, principalSubject string) error {
	if s.cache != nil && principalSubject != "" {
		return s.cache.InvalidatePrincipal(ctx, principalSubject)
	}
	return nil
}

func (s *service) InvalidateResourceCache(ctx context.Context, resourceType, resourceID string) error {
	if s.cache != nil && resourceType != "" && resourceID != "" {
		return s.cache.InvalidateResource(ctx, resourceType, resourceID)
	}
	return nil
}

func (s *service) InvalidateAllCache(ctx context.Context) error {
	if s.cache != nil {
		return s.cache.InvalidateAll(ctx)
	}
	return nil
}
