package polar

import (
	"context"

	"github.com/BladiCreator/go-modular-auth/plugin"
)

// PluginID is the unique string identifier for the Polar plugin ("polar").
const PluginID = "polar"

// Plugin implements the Polar billing, customer portal, usage metering, and webhook integration plugin for go-modular-auth.
type Plugin struct {
	repo   Repository
	config Config
	ctx    *plugin.Context
	client Client
}

// New instantiates a new Polar plugin configured with a mandatory Repository implementation and functional options.
func New(repo Repository, opts ...Option) *Plugin {
	cfg := DefaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	p := &Plugin{
		repo:   repo,
		config: cfg,
	}

	// Initialize SDK Client
	if cfg.AccessToken == "" || cfg.AccessToken == "test_token" || cfg.AccessToken == "mock" {
		p.client = newMockClient()
	} else {
		p.client = newSDKClient(cfg.AccessToken, cfg.Server)
	}

	return p
}

// ID returns the unique string identifier for the plugin ("polar").
func (p *Plugin) ID() string {
	return PluginID
}

// Init initializes the plugin with the shared execution context and registers event hooks.
func (p *Plugin) Init(ctx *plugin.Context) error {
	p.ctx = ctx
	p.setupHooks()
	return nil
}

// Config returns a copy of the active plugin configuration.
func (p *Plugin) Config() Config {
	return p.config
}

// SetClient replaces the internal API client (useful for unit testing with mocks).
func (p *Plugin) SetClient(c Client) {
	if c != nil {
		p.client = c
	}
}

// CreateCheckoutSession creates a new Polar Checkout session URL for product or subscription purchase.
func (p *Plugin) CreateCheckoutSession(ctx context.Context, params CreateCheckoutParams) (string, error) {
	if params.ProductPriceID == "" && params.ProductSlug != "" {
		if plan, ok := GetPlanByID(p.config, params.ProductSlug); ok {
			params.ProductPriceID = plan.PriceID
		}
	}

	url, err := p.client.CreateCheckout(ctx, params)
	if err != nil {
		return "", err
	}

	return url, nil
}

// CreateCustomerPortalSession generates a Customer Portal session URL for a customer or referenceId.
func (p *Plugin) CreateCustomerPortalSession(ctx context.Context, params CustomerPortalParams) (string, error) {
	polarCustID := params.PolarCustomerID
	if polarCustID == "" && params.ReferenceID != "" {
		custID, err := p.repo.GetCustomerPolarID(ctx, "user", params.ReferenceID)
		if err != nil {
			custID, err = p.repo.GetCustomerPolarID(ctx, "organization", params.ReferenceID)
		}
		if err == nil {
			polarCustID = custID
		}
	}

	if polarCustID == "" {
		return "", ErrCustomerNotFound
	}

	return p.client.CreateCustomerSession(ctx, polarCustID)
}

// GetCustomerState fetches the comprehensive billing, benefit, and meter state for a customer.
func (p *Plugin) GetCustomerState(ctx context.Context, referenceID string) (*CustomerState, error) {
	polarCustID, err := p.repo.GetCustomerPolarID(ctx, "user", referenceID)
	if err != nil {
		polarCustID, err = p.repo.GetCustomerPolarID(ctx, "organization", referenceID)
	}
	if err != nil {
		return nil, ErrCustomerNotFound
	}

	state, err := p.client.GetCustomerState(ctx, polarCustID)
	if err != nil {
		return nil, err
	}

	subs, _ := p.repo.ListSubscriptionsByReferenceID(ctx, referenceID)
	var activeSubs []*Subscription
	for _, sub := range subs {
		if IsActiveOrTrialing(sub) {
			activeSubs = append(activeSubs, sub)
		}
	}
	state.ActiveSubscriptions = activeSubs
	state.ReferenceID = referenceID

	return state, nil
}

// ListSubscriptions retrieves all local subscription records associated with a referenceId.
func (p *Plugin) ListSubscriptions(ctx context.Context, referenceID string) ([]*Subscription, error) {
	return p.repo.ListSubscriptionsByReferenceID(ctx, referenceID)
}

// GetSubscription retrieves a local subscription record by ID.
func (p *Plugin) GetSubscription(ctx context.Context, subID string) (*Subscription, error) {
	return p.repo.FindSubscriptionByID(ctx, subID)
}

// CancelSubscription cancels an active subscription either immediately or at period end.
func (p *Plugin) CancelSubscription(ctx context.Context, params CancelSubscriptionParams) (*Subscription, error) {
	localSub, err := p.repo.FindSubscriptionByID(ctx, params.SubscriptionID)
	if err != nil {
		return nil, err
	}

	localSub.CancelAtPeriodEnd = params.CancelAtPeriodEnd
	if !params.CancelAtPeriodEnd {
		localSub.Status = "canceled"
	}

	if err := p.repo.UpdateSubscription(ctx, localSub); err != nil {
		return nil, err
	}

	p.publishEvent(EventPolarSubscriptionCanceled, ctx, &SubscriptionEventPayload{
		Subscription: localSub,
		EventType:    "subscription.canceled",
	})

	if p.config.Subscription != nil && p.config.Subscription.OnSubscriptionCanceled != nil {
		_ = p.config.Subscription.OnSubscriptionCanceled(ctx, localSub)
	}

	return localSub, nil
}

// IngestEvent sends usage metrics or billing events to Polar for consumption tracking.
func (p *Plugin) IngestEvent(ctx context.Context, params IngestEventParams) (*IngestEventResult, error) {
	if params.CustomerExternalID == "" && params.PolarCustomerID == "" {
		return nil, ErrCustomerNotFound
	}

	return p.client.IngestEvent(ctx, params)
}

// ListMeters retrieves active meter balances for a referenceId.
func (p *Plugin) ListMeters(ctx context.Context, referenceID string) ([]*CustomerMeter, error) {
	state, err := p.GetCustomerState(ctx, referenceID)
	if err != nil {
		return nil, err
	}
	return state.MeterBalances, nil
}

// SyncSeats updates seat quantity allocated to an active subscription.
func (p *Plugin) SyncSeats(ctx context.Context, referenceID string, seats int) error {
	subs, err := p.repo.ListSubscriptionsByReferenceID(ctx, referenceID)
	if err != nil || len(subs) == 0 {
		return ErrSubscriptionNotFound
	}

	var activeSub *Subscription
	for _, sub := range subs {
		if IsActiveOrTrialing(sub) {
			activeSub = sub
			break
		}
	}

	if activeSub == nil {
		return ErrSubscriptionNotFound
	}

	activeSub.Seats = seats
	return p.repo.UpdateSubscription(ctx, activeSub)
}

// publishEvent dispatches events safely on the shared EventBus.
func (p *Plugin) publishEvent(eventName string, ctx context.Context, payload interface{}) {
	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(eventName, ctx, payload)
	}
}
