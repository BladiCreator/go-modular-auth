package polar

import (
	"context"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/plugins/emailpassword"
)

// setupHooks registers application lifecycle event listeners on the shared EventBus.
func (p *Plugin) setupHooks() {
	if p.ctx == nil || p.ctx.Events() == nil {
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

	// Listen for user registration events to automatically provision customer records in Polar
	p.ctx.Events().Subscribe(EventUserCreated, handler)
	p.ctx.Events().Subscribe(emailpassword.EventSignUpAfter, handler)
}

// OnUserCreated triggers customer creation in Polar for a newly registered user and persists the polarCustomerID.
func (p *Plugin) OnUserCreated(ctx context.Context, user *entity.User) error {
	if user == nil || user.ID == "" {
		return nil
	}

	// Check if customer mapping already exists
	existingID, err := p.repo.GetCustomerPolarID(ctx, "user", user.ID)
	if err == nil && existingID != "" {
		return nil
	}

	// Invoke Polar Client to create customer
	custID, err := p.client.CreateCustomer(ctx, user.Email, user.Name, user.ID)
	if err != nil {
		return err
	}

	// Persist polarCustomerID in Repository
	if err := p.repo.SaveCustomerPolarID(ctx, "user", user.ID, custID); err != nil {
		return err
	}

	// Publish EventPolarCustomerCreated to EventBus
	p.publishEvent(EventPolarCustomerCreated, ctx, &CustomerCreatedPayload{
		EntityType:      "user",
		EntityID:        user.ID,
		PolarCustomerID: custID,
		Email:           user.Email,
	})

	return nil
}
