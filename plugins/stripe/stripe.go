package stripe

import (
	"context"

	"github.com/BladiCreator/go-modular-auth/plugin"
	stripe "github.com/stripe/stripe-go/v76"
	billingportalsession "github.com/stripe/stripe-go/v76/billingportal/session"
	checkoutsession "github.com/stripe/stripe-go/v76/checkout/session"
	stripesubscription "github.com/stripe/stripe-go/v76/subscription"
)

// PluginID is the unique string identifier for the Stripe plugin ("stripe").
const PluginID = "stripe"

// Plugin implements the Stripe billing, subscription, and webhook integration plugin for go-modular-auth.
type Plugin struct {
	repo   Repository
	config Config
	ctx    *plugin.Context
}

// New instantiates a new Stripe plugin configured with a mandatory Repository implementation and functional options.
func New(repo Repository, opts ...Option) (*Plugin, error) {
	if repo == nil {
		return nil, ErrRepositoryRequired
	}

	cfg := DefaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	if cfg.StripeAPIKey != "" {
		stripe.Key = cfg.StripeAPIKey
	}

	return &Plugin{
		repo:   repo,
		config: cfg,
	}, nil
}

// ID returns the unique string identifier for the plugin ("stripe").
func (p *Plugin) ID() string {
	return PluginID
}

// Init initializes the plugin with the shared execution context.
func (p *Plugin) Init(ctx *plugin.Context) error {
	p.ctx = ctx
	return nil
}

// Config returns a copy of the active plugin configuration.
func (p *Plugin) Config() Config {
	return p.config
}

// CreateCheckoutSession creates a new Stripe Checkout Session URL for subscription purchase.
func (p *Plugin) CreateCheckoutSession(ctx context.Context, params CreateCheckoutParams) (string, error) {
	plan, ok := GetPlanByID(p.config, params.PlanID)
	if !ok {
		return "", ErrInvalidPlan
	}

	metadata := BuildMetadata(params.ReferenceID, "user", params.Metadata)

	seats := params.Seats
	if seats <= 0 {
		seats = 1
	}

	lineItems := []*stripe.CheckoutSessionLineItemParams{
		{
			Price:    stripe.String(plan.PriceID),
			Quantity: stripe.Int64(int64(seats)),
		},
	}

	sessionParams := &stripe.CheckoutSessionParams{
		Mode:               stripe.String(string(stripe.CheckoutSessionModeSubscription)),
		SuccessURL:         stripe.String(params.SuccessURL),
		CancelURL:          stripe.String(params.CancelURL),
		LineItems:          lineItems,
		ClientReferenceID:  stripe.String(params.ReferenceID),
		Metadata:           metadata,
		SubscriptionData: &stripe.CheckoutSessionSubscriptionDataParams{
			Metadata: metadata,
		},
	}

	if params.CustomerEmail != "" {
		sessionParams.CustomerEmail = stripe.String(params.CustomerEmail)
	}

	if params.TrialDays > 0 {
		sessionParams.SubscriptionData.TrialPeriodDays = stripe.Int64(int64(params.TrialDays))
	}

	sess, err := checkoutsession.New(sessionParams)
	if err != nil {
		return "", err
	}

	return sess.URL, nil
}

// UpgradeSubscription updates an existing subscription to a new plan or seat count.
func (p *Plugin) UpgradeSubscription(ctx context.Context, params UpgradeSubscriptionParams) (*Subscription, error) {
	localSub, err := p.repo.FindSubscriptionByID(ctx, params.SubscriptionID)
	if err != nil {
		return nil, err
	}

	plan, ok := GetPlanByID(p.config, params.NewPlanID)
	if !ok {
		return nil, ErrInvalidPlan
	}

	stripeSub, err := stripesubscription.Get(localSub.StripeSubscriptionID, nil)
	if err != nil {
		return nil, err
	}

	var items []*stripe.SubscriptionItemsParams
	if len(stripeSub.Items.Data) > 0 {
		items = append(items, &stripe.SubscriptionItemsParams{
			ID:    stripe.String(stripeSub.Items.Data[0].ID),
			Price: stripe.String(plan.PriceID),
		})
	}

	subParams := &stripe.SubscriptionParams{
		Items: items,
	}

	if params.Seats > 0 {
		subParams.Items[0].Quantity = stripe.Int64(int64(params.Seats))
	}

	updatedStripeSub, err := stripesubscription.Update(localSub.StripeSubscriptionID, subParams)
	if err != nil {
		return nil, err
	}

	updatedLocalSub := mapStripeSubscriptionToLocal(updatedStripeSub, localSub.ReferenceID, p.config)
	updatedLocalSub.ID = localSub.ID

	if err := p.repo.UpdateSubscription(ctx, updatedLocalSub); err != nil {
		return nil, err
	}

	p.publishEvent(EventStripeSubscriptionUpdated, ctx, &SubscriptionEventPayload{
		Subscription: updatedLocalSub,
		EventType:    "subscription.upgraded",
	})

	return updatedLocalSub, nil
}

// CancelSubscription cancels a subscription either immediately or at period end.
func (p *Plugin) CancelSubscription(ctx context.Context, params CancelSubscriptionParams) (*Subscription, error) {
	localSub, err := p.repo.FindSubscriptionByID(ctx, params.SubscriptionID)
	if err != nil {
		return nil, err
	}

	var updatedStripeSub *stripe.Subscription
	if params.CancelAtPeriodEnd {
		subParams := &stripe.SubscriptionParams{
			CancelAtPeriodEnd: stripe.Bool(true),
		}
		updatedStripeSub, err = stripesubscription.Update(localSub.StripeSubscriptionID, subParams)
	} else {
		updatedStripeSub, err = stripesubscription.Cancel(localSub.StripeSubscriptionID, nil)
	}
	if err != nil {
		return nil, err
	}

	updatedLocalSub := mapStripeSubscriptionToLocal(updatedStripeSub, localSub.ReferenceID, p.config)
	updatedLocalSub.ID = localSub.ID

	if err := p.repo.UpdateSubscription(ctx, updatedLocalSub); err != nil {
		return nil, err
	}

	p.publishEvent(EventStripeSubscriptionDeleted, ctx, &SubscriptionEventPayload{
		Subscription: updatedLocalSub,
		EventType:    "subscription.canceled",
	})

	return updatedLocalSub, nil
}

// RestoreSubscription revokes a scheduled cancellation at period end.
func (p *Plugin) RestoreSubscription(ctx context.Context, subID string) (*Subscription, error) {
	localSub, err := p.repo.FindSubscriptionByID(ctx, subID)
	if err != nil {
		return nil, err
	}

	subParams := &stripe.SubscriptionParams{
		CancelAtPeriodEnd: stripe.Bool(false),
	}

	updatedStripeSub, err := stripesubscription.Update(localSub.StripeSubscriptionID, subParams)
	if err != nil {
		return nil, err
	}

	updatedLocalSub := mapStripeSubscriptionToLocal(updatedStripeSub, localSub.ReferenceID, p.config)
	updatedLocalSub.ID = localSub.ID

	if err := p.repo.UpdateSubscription(ctx, updatedLocalSub); err != nil {
		return nil, err
	}

	p.publishEvent(EventStripeSubscriptionUpdated, ctx, &SubscriptionEventPayload{
		Subscription: updatedLocalSub,
		EventType:    "subscription.restored",
	})

	return updatedLocalSub, nil
}

// CreateBillingPortalSession creates a new Stripe Customer Billing Portal session URL.
func (p *Plugin) CreateBillingPortalSession(ctx context.Context, params BillingPortalParams) (string, error) {
	portalParams := &stripe.BillingPortalSessionParams{
		Customer:  stripe.String(params.StripeCustomerID),
		ReturnURL: stripe.String(params.ReturnURL),
	}

	sess, err := billingportalsession.New(portalParams)
	if err != nil {
		return "", err
	}

	return sess.URL, nil
}

// GetSubscription retrieves a local subscription record by ID.
func (p *Plugin) GetSubscription(ctx context.Context, subID string) (*Subscription, error) {
	return p.repo.FindSubscriptionByID(ctx, subID)
}

// ListSubscriptions retrieves all subscriptions linked to a referenceId.
func (p *Plugin) ListSubscriptions(ctx context.Context, referenceID string) ([]*Subscription, error) {
	return p.repo.ListSubscriptionsByReferenceID(ctx, referenceID)
}

// SyncSeats updates the seat count quantity in Stripe for an active subscription linked to a referenceId.
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

	stripeSub, err := stripesubscription.Get(activeSub.StripeSubscriptionID, nil)
	if err != nil {
		return err
	}

	if len(stripeSub.Items.Data) == 0 {
		return nil
	}

	subParams := &stripe.SubscriptionParams{
		Items: []*stripe.SubscriptionItemsParams{
			{
				ID:       stripe.String(stripeSub.Items.Data[0].ID),
				Quantity: stripe.Int64(int64(seats)),
			},
		},
	}

	updatedSub, err := stripesubscription.Update(activeSub.StripeSubscriptionID, subParams)
	if err != nil {
		return err
	}

	localSub := mapStripeSubscriptionToLocal(updatedSub, referenceID, p.config)
	localSub.ID = activeSub.ID
	return p.repo.UpdateSubscription(ctx, localSub)
}

// publishEvent dispatches events safely on the shared EventBus.
func (p *Plugin) publishEvent(eventName string, ctx context.Context, payload interface{}) {
	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(eventName, ctx, payload)
	}
}
