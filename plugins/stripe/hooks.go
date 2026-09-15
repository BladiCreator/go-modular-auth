package stripe

import (
	"context"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/plugins/emailpassword"
	stripsdk "github.com/stripe/stripe-go/v76"
	stripecustomer "github.com/stripe/stripe-go/v76/customer"
)

// setupHooks registers application lifecycle event listeners on the shared Hooks dispatcher.
func (p *Plugin) setupHooks() {
	if p.ctx == nil || p.ctx.Hooks() == nil {
		return
	}

	handler := func(ctx context.Context, payload any) {
		if !p.config.CreateCustomerOnSignUp {
			return
		}

		var user *entity.User
		switch v := payload.(type) {
		case *entity.User:
			user = v
		case *emailpassword.SignUpEventPayload:
			if v != nil {
				user = v.User
			}
		}

		if user != nil && user.ID != "" {
			_ = p.OnUserCreated(ctx, user)
		}
	}

	// Listen for user registration events to automatically provision customer records in Stripe
	p.ctx.Hooks().Subscribe(EventUserCreated, handler)
	p.ctx.Hooks().Subscribe(emailpassword.EventSignUpAfter, handler)
	p.ctx.Hooks().OnUserSignedUp(func(ctx context.Context, user *entity.User) {
		if p.config.CreateCustomerOnSignUp && user != nil && user.ID != "" {
			_ = p.OnUserCreated(ctx, user)
		}
	})
}

// OnUserCreated triggers customer creation in Stripe for a newly registered user and persists the stripeCustomerID.
func (p *Plugin) OnUserCreated(ctx context.Context, user *entity.User) error {
	if user == nil || user.ID == "" {
		return nil
	}

	// Check if customer mapping already exists
	existingID, err := p.repo.GetCustomerStripeID(ctx, "user", user.ID)
	if err == nil && existingID != "" {
		return nil
	}

	params := &stripsdk.CustomerParams{
		Email: new(user.Email),
		Name:  new(user.Name),
		Metadata: map[string]string{
			"user_id":      user.ID,
			"reference_id": user.ID,
		},
	}

	cust, err := stripecustomer.New(params)
	if err != nil {
		return err
	}

	// Persist stripeCustomerID in Repository
	if err := p.repo.SaveCustomerStripeID(ctx, "user", user.ID, cust.ID); err != nil {
		return err
	}

	// Publish EventStripeCustomerCreated to Hooks dispatcher
	p.publishEvent(EventStripeCustomerCreated, ctx, &CustomerCreatedPayload{
		EntityType:       "user",
		EntityID:         user.ID,
		StripeCustomerID: cust.ID,
		Email:            user.Email,
	})

	return nil
}
