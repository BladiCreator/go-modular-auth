package stripe

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	stripe "github.com/stripe/stripe-go/v76"
	"github.com/stripe/stripe-go/v76/webhook"
)

// ProcessWebhook parses raw body bytes, verifies the Stripe-Signature cryptographic header,
// and processes supported event types (Checkout sessions, Subscriptions, Invoices).
func (p *Plugin) ProcessWebhook(ctx context.Context, payload []byte, signature string) error {
	if p.config.WebhookSecret == "" {
		return fmt.Errorf("%w: webhook secret not configured", ErrInvalidWebhookSignature)
	}

	event, err := webhook.ConstructEvent(payload, signature, p.config.WebhookSecret)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidWebhookSignature, err)
	}

	// Publish EventStripeWebhookReceived on EventBus
	p.publishEvent(EventStripeWebhookReceived, ctx, &WebhookReceivedPayload{
		StripeEventID: event.ID,
		EventType:     string(event.Type),
		RawPayload:    payload,
	})

	switch event.Type {
	case "checkout.session.completed":
		var session stripe.CheckoutSession
		if err := json.Unmarshal(event.Data.Raw, &session); err != nil {
			return fmt.Errorf("stripe: failed to unmarshal checkout session: %w", err)
		}
		return p.handleCheckoutSessionCompleted(ctx, &session, event.ID)

	case "customer.subscription.created":
		var sub stripe.Subscription
		if err := json.Unmarshal(event.Data.Raw, &sub); err != nil {
			return fmt.Errorf("stripe: failed to unmarshal subscription: %w", err)
		}
		return p.handleCustomerSubscriptionCreated(ctx, &sub, event.ID)

	case "customer.subscription.updated":
		var sub stripe.Subscription
		if err := json.Unmarshal(event.Data.Raw, &sub); err != nil {
			return fmt.Errorf("stripe: failed to unmarshal subscription: %w", err)
		}
		return p.handleCustomerSubscriptionUpdated(ctx, &sub, event.ID)

	case "customer.subscription.deleted":
		var sub stripe.Subscription
		if err := json.Unmarshal(event.Data.Raw, &sub); err != nil {
			return fmt.Errorf("stripe: failed to unmarshal subscription: %w", err)
		}
		return p.handleCustomerSubscriptionDeleted(ctx, &sub, event.ID)

	case "invoice.payment_succeeded":
		var inv stripe.Invoice
		if err := json.Unmarshal(event.Data.Raw, &inv); err != nil {
			return fmt.Errorf("stripe: failed to unmarshal invoice: %w", err)
		}
		return p.handleInvoicePaymentSucceeded(ctx, &inv, event.ID)

	case "invoice.payment_failed":
		var inv stripe.Invoice
		if err := json.Unmarshal(event.Data.Raw, &inv); err != nil {
			return fmt.Errorf("stripe: failed to unmarshal invoice: %w", err)
		}
		return p.handleInvoicePaymentFailed(ctx, &inv, event.ID)

	default:
		// Unhandled event type, silently succeed
		return nil
	}
}

func (p *Plugin) handleCheckoutSessionCompleted(ctx context.Context, session *stripe.CheckoutSession, eventID string) error {
	if session == nil {
		return nil
	}

	referenceID, _, ok := ExtractReferenceID(session.Metadata)
	if !ok && session.ClientReferenceID != "" {
		referenceID = session.ClientReferenceID
	}

	custID := ""
	if session.Customer != nil {
		custID = session.Customer.ID
	}

	subID := ""
	if session.Subscription != nil {
		subID = session.Subscription.ID
	}

	if referenceID != "" && custID != "" {
		_ = p.repo.SaveCustomerStripeID(ctx, "user", referenceID, custID)
	}

	if subID == "" {
		return nil
	}

	// Fetch or update existing subscription record
	localSub, err := p.repo.FindSubscriptionByStripeID(ctx, subID)
	if err != nil {
		localSub = &Subscription{
			ReferenceID:          referenceID,
			StripeCustomerID:     custID,
			StripeSubscriptionID: subID,
			Status:               StatusActive,
			CreatedAt:            time.Now(),
		}
		if err := p.repo.CreateSubscription(ctx, localSub); err != nil {
			return err
		}
	} else {
		localSub.Status = StatusActive
		if err := p.repo.UpdateSubscription(ctx, localSub); err != nil {
			return err
		}
	}

	p.publishEvent(EventStripeSubscriptionCreated, ctx, &SubscriptionEventPayload{
		Subscription:  localSub,
		StripeEventID: eventID,
		EventType:     "checkout.session.completed",
	})

	if p.config.Subscription != nil && p.config.Subscription.OnSubscriptionCompleted != nil {
		_ = p.config.Subscription.OnSubscriptionCompleted(ctx, localSub)
	}

	return nil
}

func (p *Plugin) handleCustomerSubscriptionCreated(ctx context.Context, stripeSub *stripe.Subscription, eventID string) error {
	if stripeSub == nil {
		return nil
	}

	referenceID, _, ok := ExtractReferenceID(stripeSub.Metadata)
	if !ok {
		// Attempt to look up existing customer mapping
		if stripeSub.Customer != nil {
			referenceID = stripeSub.Customer.ID
		}
	}

	sub := mapStripeSubscriptionToLocal(stripeSub, referenceID, p.config)

	existing, err := p.repo.FindSubscriptionByStripeID(ctx, stripeSub.ID)
	if err != nil {
		if err := p.repo.CreateSubscription(ctx, sub); err != nil {
			return err
		}
	} else {
		sub.ID = existing.ID
		if err := p.repo.UpdateSubscription(ctx, sub); err != nil {
			return err
		}
	}

	p.publishEvent(EventStripeSubscriptionCreated, ctx, &SubscriptionEventPayload{
		Subscription:  sub,
		StripeEventID: eventID,
		EventType:     "customer.subscription.created",
	})

	if p.config.Subscription != nil && p.config.Subscription.OnSubscriptionCreated != nil {
		_ = p.config.Subscription.OnSubscriptionCreated(ctx, sub)
	}

	return nil
}

func (p *Plugin) handleCustomerSubscriptionUpdated(ctx context.Context, stripeSub *stripe.Subscription, eventID string) error {
	if stripeSub == nil {
		return nil
	}

	existing, err := p.repo.FindSubscriptionByStripeID(ctx, stripeSub.ID)
	referenceID := ""
	if err == nil && existing != nil {
		referenceID = existing.ReferenceID
	} else {
		extracted, _, ok := ExtractReferenceID(stripeSub.Metadata)
		if ok {
			referenceID = extracted
		}
	}

	sub := mapStripeSubscriptionToLocal(stripeSub, referenceID, p.config)
	if existing != nil {
		sub.ID = existing.ID
		if err := p.repo.UpdateSubscription(ctx, sub); err != nil {
			return err
		}
	} else {
		if err := p.repo.CreateSubscription(ctx, sub); err != nil {
			return err
		}
	}

	p.publishEvent(EventStripeSubscriptionUpdated, ctx, &SubscriptionEventPayload{
		Subscription:  sub,
		StripeEventID: eventID,
		EventType:     "customer.subscription.updated",
	})

	if p.config.Subscription != nil && p.config.Subscription.OnSubscriptionUpdated != nil {
		_ = p.config.Subscription.OnSubscriptionUpdated(ctx, sub)
	}

	return nil
}

func (p *Plugin) handleCustomerSubscriptionDeleted(ctx context.Context, stripeSub *stripe.Subscription, eventID string) error {
	if stripeSub == nil {
		return nil
	}

	existing, err := p.repo.FindSubscriptionByStripeID(ctx, stripeSub.ID)
	if err != nil || existing == nil {
		return nil
	}

	existing.Status = StatusCanceled
	now := time.Now()
	existing.EndedAt = &now
	if err := p.repo.UpdateSubscription(ctx, existing); err != nil {
		return err
	}

	p.publishEvent(EventStripeSubscriptionDeleted, ctx, &SubscriptionEventPayload{
		Subscription:  existing,
		StripeEventID: eventID,
		EventType:     "customer.subscription.deleted",
	})

	if p.config.Subscription != nil && p.config.Subscription.OnSubscriptionDeleted != nil {
		_ = p.config.Subscription.OnSubscriptionDeleted(ctx, existing)
	}

	return nil
}

func (p *Plugin) handleInvoicePaymentSucceeded(ctx context.Context, inv *stripe.Invoice, eventID string) error {
	if inv == nil {
		return nil
	}

	invData := mapStripeInvoiceToData(inv)

	// If linked to a subscription, update state to active if needed
	if invData.StripeSubscriptionID != "" {
		sub, err := p.repo.FindSubscriptionByStripeID(ctx, invData.StripeSubscriptionID)
		if err == nil && sub != nil {
			sub.Status = StatusActive
			_ = p.repo.UpdateSubscription(ctx, sub)
		}
	}

	p.publishEvent(EventStripeInvoicePaymentSucceeded, ctx, &InvoiceEventPayload{
		Invoice:       invData,
		StripeEventID: eventID,
		EventType:     "invoice.payment_succeeded",
	})

	if p.config.Subscription != nil && p.config.Subscription.OnInvoicePaymentSucceeded != nil {
		_ = p.config.Subscription.OnInvoicePaymentSucceeded(ctx, invData)
	}

	return nil
}

func (p *Plugin) handleInvoicePaymentFailed(ctx context.Context, inv *stripe.Invoice, eventID string) error {
	if inv == nil {
		return nil
	}

	invData := mapStripeInvoiceToData(inv)

	if invData.StripeSubscriptionID != "" {
		sub, err := p.repo.FindSubscriptionByStripeID(ctx, invData.StripeSubscriptionID)
		if err == nil && sub != nil {
			sub.Status = StatusPastDue
			_ = p.repo.UpdateSubscription(ctx, sub)
		}
	}

	p.publishEvent(EventStripeInvoicePaymentFailed, ctx, &InvoiceEventPayload{
		Invoice:       invData,
		StripeEventID: eventID,
		EventType:     "invoice.payment_failed",
	})

	if p.config.Subscription != nil && p.config.Subscription.OnInvoicePaymentFailed != nil {
		_ = p.config.Subscription.OnInvoicePaymentFailed(ctx, invData)
	}

	return nil
}

func mapStripeSubscriptionToLocal(s *stripe.Subscription, referenceID string, cfg Config) *Subscription {
	custID := ""
	if s.Customer != nil {
		custID = s.Customer.ID
	}

	planID := ""
	seats := 1
	interval := "month"

	if len(s.Items.Data) > 0 {
		item := s.Items.Data[0]
		if item.Price != nil {
			planID = item.Price.ID
			if plan, ok := GetPlanByPriceID(cfg, item.Price.ID); ok {
				planID = plan.ID
			}
			if item.Price.Recurring != nil {
				interval = string(item.Price.Recurring.Interval)
			}
		}
		if item.Quantity > 0 {
			seats = int(item.Quantity)
		}
	}

	sub := &Subscription{
		Plan:                 planID,
		ReferenceID:          referenceID,
		StripeCustomerID:     custID,
		StripeSubscriptionID: s.ID,
		Status:               SubscriptionStatus(s.Status),
		PeriodStart:          time.Unix(s.CurrentPeriodStart, 0),
		PeriodEnd:            time.Unix(s.CurrentPeriodEnd, 0),
		CancelAtPeriodEnd:    s.CancelAtPeriodEnd,
		Seats:                seats,
		BillingInterval:      interval,
		CreatedAt:            time.Unix(s.Created, 0),
	}

	if s.TrialStart > 0 {
		t := time.Unix(s.TrialStart, 0)
		sub.TrialStart = &t
	}
	if s.TrialEnd > 0 {
		t := time.Unix(s.TrialEnd, 0)
		sub.TrialEnd = &t
	}
	if s.CancelAt > 0 {
		t := time.Unix(s.CancelAt, 0)
		sub.CancelAt = &t
	}
	if s.CanceledAt > 0 {
		t := time.Unix(s.CanceledAt, 0)
		sub.CanceledAt = &t
	}
	if s.EndedAt > 0 {
		t := time.Unix(s.EndedAt, 0)
		sub.EndedAt = &t
	}

	return sub
}

func mapStripeInvoiceToData(inv *stripe.Invoice) *InvoiceData {
	custID := ""
	if inv.Customer != nil {
		custID = inv.Customer.ID
	}

	subID := ""
	if inv.Subscription != nil {
		subID = inv.Subscription.ID
	}

	return &InvoiceData{
		InvoiceID:            inv.ID,
		StripeCustomerID:     custID,
		StripeSubscriptionID: subID,
		AmountPaid:           inv.AmountPaid,
		Currency:             string(inv.Currency),
		Status:               string(inv.Status),
		PaidAt:               time.Unix(inv.StatusTransitions.PaidAt, 0),
	}
}
