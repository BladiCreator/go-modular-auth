package polar

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ProcessWebhook parses raw body bytes, verifies the cryptographic signature header,
// and processes supported Polar webhook event types.
func (p *Plugin) ProcessWebhook(ctx context.Context, payload []byte, signature string) error {
	if p.config.WebhookSecret != "" {
		if err := verifyWebhookSignature(payload, signature, p.config.WebhookSecret); err != nil {
			return err
		}
	}

	var event genericWebhookEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		return fmt.Errorf("polar: failed to unmarshal webhook payload: %w", err)
	}

	p.publishEvent(EventPolarWebhookReceived, ctx, &WebhookReceivedPayload{
		PolarEventID: event.ID,
		EventType:    event.Type,
		RawPayload:   payload,
	})

	switch event.Type {
	case "subscription.created":
		return p.handleSubscriptionCreated(ctx, payload, event.ID)

	case "subscription.updated", "subscription.active":
		return p.handleSubscriptionUpdated(ctx, payload, event.ID)

	case "subscription.canceled", "subscription.revoked":
		return p.handleSubscriptionCanceled(ctx, payload, event.ID)

	case "customer.state_changed":
		return p.handleCustomerStateChanged(ctx, payload, event.ID)

	case "order.created", "order.paid":
		return p.handleOrderPaid(ctx, payload, event.ID)

	case "benefit.created", "benefit.granted":
		return p.handleBenefitGranted(ctx, payload, event.ID)

	case "benefit.revoked":
		return p.handleBenefitRevoked(ctx, payload, event.ID)

	default:
		// Unhandled event type, return nil for graceful processing
		return nil
	}
}

type genericWebhookEvent struct {
	ID   string          `json:"id"`
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

type webhookSubscriptionData struct {
	ID                 string            `json:"id"`
	CustomerID         string            `json:"customer_id"`
	CustomerExternalID string            `json:"customer_external_id"`
	ProductID          string            `json:"product_id"`
	PriceID            string            `json:"price_id"`
	Status             string            `json:"status"`
	Amount             int64             `json:"amount"`
	Currency           string            `json:"currency"`
	RecurringInterval  string            `json:"recurring_interval"`
	CurrentPeriodStart time.Time         `json:"current_period_start"`
	CurrentPeriodEnd   time.Time         `json:"current_period_end"`
	CancelAtPeriodEnd  bool              `json:"cancel_at_period_end"`
	Metadata           map[string]string `json:"metadata"`
}

func (p *Plugin) handleSubscriptionCreated(ctx context.Context, payload []byte, eventID string) error {
	var event struct {
		Data webhookSubscriptionData `json:"data"`
	}
	if err := json.Unmarshal(payload, &event); err != nil {
		return err
	}

	subData := event.Data
	refID := subData.CustomerExternalID
	if refID == "" && subData.Metadata != nil {
		refID = subData.Metadata["reference_id"]
	}

	sub := &Subscription{
		PolarSubscriptionID: subData.ID,
		PolarCustomerID:     subData.CustomerID,
		ReferenceID:         refID,
		ProductID:           subData.ProductID,
		PriceID:             subData.PriceID,
		Status:              subData.Status,
		Amount:              subData.Amount,
		Currency:            subData.Currency,
		Interval:            subData.RecurringInterval,
		CurrentPeriodStart:  subData.CurrentPeriodStart,
		CurrentPeriodEnd:    subData.CurrentPeriodEnd,
		CancelAtPeriodEnd:   subData.CancelAtPeriodEnd,
		Metadata:            subData.Metadata,
	}

	if err := p.repo.CreateSubscription(ctx, sub); err != nil {
		return err
	}

	p.publishEvent(EventPolarSubscriptionCreated, ctx, &SubscriptionEventPayload{
		Subscription: sub,
		PolarEventID: eventID,
		EventType:    "subscription.created",
	})

	if p.config.Subscription != nil && p.config.Subscription.OnSubscriptionCreated != nil {
		_ = p.config.Subscription.OnSubscriptionCreated(ctx, sub)
	}

	return nil
}

func (p *Plugin) handleSubscriptionUpdated(ctx context.Context, payload []byte, eventID string) error {
	var event struct {
		Data webhookSubscriptionData `json:"data"`
	}
	if err := json.Unmarshal(payload, &event); err != nil {
		return err
	}

	subData := event.Data
	localSub, err := p.repo.FindSubscriptionByPolarID(ctx, subData.ID)
	if err != nil {
		refID := subData.CustomerExternalID
		if refID == "" && subData.Metadata != nil {
			refID = subData.Metadata["reference_id"]
		}
		localSub = &Subscription{
			PolarSubscriptionID: subData.ID,
			PolarCustomerID:     subData.CustomerID,
			ReferenceID:         refID,
		}
	}

	localSub.Status = subData.Status
	localSub.Amount = subData.Amount
	localSub.Currency = subData.Currency
	localSub.CurrentPeriodStart = subData.CurrentPeriodStart
	localSub.CurrentPeriodEnd = subData.CurrentPeriodEnd
	localSub.CancelAtPeriodEnd = subData.CancelAtPeriodEnd
	if subData.Metadata != nil {
		localSub.Metadata = subData.Metadata
	}

	if localSub.ID == "" {
		_ = p.repo.CreateSubscription(ctx, localSub)
	} else {
		_ = p.repo.UpdateSubscription(ctx, localSub)
	}

	p.publishEvent(EventPolarSubscriptionUpdated, ctx, &SubscriptionEventPayload{
		Subscription: localSub,
		PolarEventID: eventID,
		EventType:    "subscription.updated",
	})

	if p.config.Subscription != nil && p.config.Subscription.OnSubscriptionUpdated != nil {
		_ = p.config.Subscription.OnSubscriptionUpdated(ctx, localSub)
	}

	return nil
}

func (p *Plugin) handleSubscriptionCanceled(ctx context.Context, payload []byte, eventID string) error {
	var event struct {
		Data webhookSubscriptionData `json:"data"`
	}
	if err := json.Unmarshal(payload, &event); err != nil {
		return err
	}

	subData := event.Data
	localSub, err := p.repo.FindSubscriptionByPolarID(ctx, subData.ID)
	if err != nil {
		return nil
	}

	localSub.Status = "canceled"
	localSub.CancelAtPeriodEnd = false
	_ = p.repo.UpdateSubscription(ctx, localSub)

	p.publishEvent(EventPolarSubscriptionCanceled, ctx, &SubscriptionEventPayload{
		Subscription: localSub,
		PolarEventID: eventID,
		EventType:    "subscription.canceled",
	})

	if p.config.Subscription != nil && p.config.Subscription.OnSubscriptionCanceled != nil {
		_ = p.config.Subscription.OnSubscriptionCanceled(ctx, localSub)
	}

	return nil
}

func (p *Plugin) handleCustomerStateChanged(ctx context.Context, payload []byte, eventID string) error {
	var event struct {
		Data struct {
			CustomerID string `json:"customer_id"`
			ExternalID string `json:"external_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(payload, &event); err != nil {
		return err
	}

	refID := event.Data.ExternalID
	state, err := p.GetCustomerState(ctx, refID)
	if err != nil {
		state = &CustomerState{
			PolarCustomerID: event.Data.CustomerID,
			ReferenceID:     refID,
		}
	}

	p.publishEvent(EventPolarCustomerStateChanged, ctx, &CustomerStateEventPayload{
		CustomerState: state,
		PolarEventID:  eventID,
		EventType:     "customer.state_changed",
	})

	if p.config.Subscription != nil && p.config.Subscription.OnCustomerStateChanged != nil {
		_ = p.config.Subscription.OnCustomerStateChanged(ctx, state)
	}

	return nil
}

func (p *Plugin) handleOrderPaid(ctx context.Context, payload []byte, eventID string) error {
	var event struct {
		Data struct {
			ID       string `json:"id"`
			Amount   int64  `json:"amount"`
			Currency string `json:"currency"`
			Status   string `json:"status"`
		} `json:"data"`
	}
	if err := json.Unmarshal(payload, &event); err != nil {
		return err
	}

	order := &CustomerOrder{
		PolarOrderID: event.Data.ID,
		Amount:       event.Data.Amount,
		Currency:     event.Data.Currency,
		Status:       event.Data.Status,
		CreatedAt:    time.Now(),
	}

	p.publishEvent(EventPolarOrderPaid, ctx, &OrderEventPayload{
		Order:        order,
		PolarEventID: eventID,
		EventType:    "order.paid",
	})

	if p.config.Subscription != nil && p.config.Subscription.OnOrderPaid != nil {
		_ = p.config.Subscription.OnOrderPaid(ctx, order)
	}

	return nil
}

func (p *Plugin) handleBenefitGranted(ctx context.Context, payload []byte, eventID string) error {
	var event struct {
		Data struct {
			ID          string `json:"id"`
			BenefitID   string `json:"benefit_id"`
			Type        string `json:"type"`
			Description string `json:"description"`
		} `json:"data"`
	}
	if err := json.Unmarshal(payload, &event); err != nil {
		return err
	}

	benefit := &CustomerBenefit{
		ID:             event.Data.ID,
		PolarBenefitID: event.Data.BenefitID,
		Type:           event.Data.Type,
		Description:    event.Data.Description,
		GrantedAt:      time.Now(),
	}

	p.publishEvent(EventPolarBenefitGranted, ctx, &BenefitEventPayload{
		Benefit:      benefit,
		PolarEventID: eventID,
		EventType:    "benefit.granted",
	})

	if p.config.Subscription != nil && p.config.Subscription.OnBenefitGranted != nil {
		_ = p.config.Subscription.OnBenefitGranted(ctx, benefit)
	}

	return nil
}

func (p *Plugin) handleBenefitRevoked(ctx context.Context, payload []byte, eventID string) error {
	var event struct {
		Data struct {
			ID          string `json:"id"`
			BenefitID   string `json:"benefit_id"`
			Type        string `json:"type"`
			Description string `json:"description"`
		} `json:"data"`
	}
	if err := json.Unmarshal(payload, &event); err != nil {
		return err
	}

	benefit := &CustomerBenefit{
		ID:             event.Data.ID,
		PolarBenefitID: event.Data.BenefitID,
		Type:           event.Data.Type,
		Description:    event.Data.Description,
		GrantedAt:      time.Now(),
	}

	p.publishEvent(EventPolarBenefitRevoked, ctx, &BenefitEventPayload{
		Benefit:      benefit,
		PolarEventID: eventID,
		EventType:    "benefit.revoked",
	})

	if p.config.Subscription != nil && p.config.Subscription.OnBenefitRevoked != nil {
		_ = p.config.Subscription.OnBenefitRevoked(ctx, benefit)
	}

	return nil
}

func verifyWebhookSignature(payload []byte, signature, secret string) error {
	if signature == "" {
		return ErrInvalidWebhookSignature
	}

	sig := signature
	if strings.Contains(signature, "v1=") {
		parts := strings.Split(signature, ",")
		for _, part := range parts {
			if strings.HasPrefix(strings.TrimSpace(part), "v1=") {
				sig = strings.TrimPrefix(strings.TrimSpace(part), "v1=")
				break
			}
		}
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	expectedMAC := hex.EncodeToString(mac.Sum(nil))

	if hmac.Equal([]byte(sig), []byte(expectedMAC)) {
		return nil
	}

	return ErrInvalidWebhookSignature
}
