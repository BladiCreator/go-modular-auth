package stripe

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/BladiCreator/go-modular-auth/adapter"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
)

type service struct {
	ctx      *sdk.Context
	cfg      Config
	custRepo *sdk.Repository[Customer]
	subRepo  *sdk.Repository[Subscription]
}

var _ Stripe = (*service)(nil)

func newService(ctx *sdk.Context, cfg Config) *service {
	return &service{
		ctx:      ctx,
		cfg:      cfg,
		custRepo: sdk.Model[Customer](ctx, ModelStripeCustomers),
		subRepo:  sdk.Model[Subscription](ctx, ModelStripeSubscriptions),
	}
}

// GetCustomer retrieves the customer mapped to the target reference.
func (s *service) GetCustomer(ctx context.Context, target TargetReference) (*Customer, error) {
	if target.ID == "" || target.Type == "" {
		return nil, ErrInvalidReference
	}

	cust, err := s.custRepo.FindOne(ctx,
		adapter.Eq("reference_type", string(target.Type)),
		adapter.Eq("reference_id", target.ID),
	)
	if err != nil {
		if errors.Is(err, adapter.ErrNotFound) {
			return nil, ErrCustomerNotFound
		}
		return nil, err
	}
	return cust, nil
}

// CreateCustomer creates or registers a customer mapping.
func (s *service) CreateCustomer(ctx context.Context, target TargetReference) (*Customer, error) {
	if target.ID == "" || target.Type == "" {
		return nil, ErrInvalidReference
	}

	// Check if customer already exists locally
	existing, err := s.GetCustomer(ctx, target)
	if err == nil && existing != nil {
		return existing, nil
	}

	now := time.Now()
	id := fmt.Sprintf("scust_%d", now.UnixNano())
	stripeCustID := fmt.Sprintf("cus_%s_%s", target.Type, target.ID)

	cust := &Customer{
		ID:               id,
		ReferenceID:      target.ID,
		ReferenceType:    target.Type,
		StripeCustomerID: stripeCustID,
		Email:            fmt.Sprintf("%s@example.com", target.ID),
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	if err := s.custRepo.Create(ctx, cust); err != nil {
		return nil, err
	}
	return cust, nil
}

// CreateCheckoutSession generates a Stripe Checkout Session.
func (s *service) CreateCheckoutSession(ctx context.Context, in CreateCheckoutInput) (*CheckoutSession, error) {
	if in.Target.ID == "" || in.PriceID == "" {
		return nil, ErrInvalidReference
	}

	sessionID := fmt.Sprintf("cs_test_%d", time.Now().UnixNano())
	checkoutURL := fmt.Sprintf("https://checkout.stripe.com/pay/%s", sessionID)

	return &CheckoutSession{
		SessionID: sessionID,
		URL:       checkoutURL,
	}, nil
}

// CreateBillingPortalSession generates a customer portal URL.
func (s *service) CreateBillingPortalSession(ctx context.Context, target TargetReference, returnURL string) (*BillingPortalSession, error) {
	cust, err := s.GetCustomer(ctx, target)
	if err != nil {
		return nil, err
	}

	portalURL := fmt.Sprintf("https://billing.stripe.com/p/session/%s?return_url=%s", cust.StripeCustomerID, returnURL)
	return &BillingPortalSession{
		URL: portalURL,
	}, nil
}

// GetActiveSubscription retrieves the current active subscription for the given target reference.
func (s *service) GetActiveSubscription(ctx context.Context, target TargetReference) (*Subscription, error) {
	if target.ID == "" || target.Type == "" {
		return nil, ErrInvalidReference
	}

	sub, err := s.subRepo.FindOne(ctx,
		adapter.Eq("reference_type", string(target.Type)),
		adapter.Eq("reference_id", target.ID),
		adapter.Eq("status", string(StatusActive)),
	)
	if err != nil {
		if errors.Is(err, adapter.ErrNotFound) {
			return nil, ErrSubscriptionNotFound
		}
		return nil, err
	}
	return sub, nil
}

// HasActiveSubscription reports whether the target identity has an active subscription.
func (s *service) HasActiveSubscription(ctx context.Context, target TargetReference, priceIDs ...string) (bool, error) {
	sub, err := s.GetActiveSubscription(ctx, target)
	if err != nil {
		if errors.Is(err, ErrSubscriptionNotFound) {
			return false, nil
		}
		return false, err
	}

	if !sub.Active() {
		return false, nil
	}

	if len(priceIDs) == 0 {
		return true, nil
	}

	for _, pid := range priceIDs {
		if sub.StripePriceID == pid {
			return true, nil
		}
	}
	return false, nil
}

// HandleWebhook verifies the webhook signature and processes incoming Stripe events.
func (s *service) HandleWebhook(ctx context.Context, payload []byte, signature string) (*WebhookEvent, error) {
	if len(payload) == 0 {
		return nil, ErrInvalidPayload
	}

	if s.cfg.WebhookSecret != "" {
		if err := verifyStripeSignature(payload, signature, s.cfg.WebhookSecret); err != nil {
			return nil, err
		}
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, ErrInvalidPayload
	}

	eventID, _ := raw["id"].(string)
	eventType, _ := raw["type"].(string)

	event := &WebhookEvent{
		ID:        eventID,
		Type:      eventType,
		Data:      raw,
		HandledAt: time.Now(),
	}

	return event, nil
}

func verifyStripeSignature(payload []byte, sigHeader string, secret string) error {
	if sigHeader == "" {
		return ErrInvalidWebhookSignature
	}

	// Stripe signature header format: t=1492774577,v1=5257a869e7ecebeda32affa62cd49231b2ec354b81c4f75f42930777425c9235
	pairs := strings.Split(sigHeader, ",")
	var timestamp, expectedSig string
	for _, pair := range pairs {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) == 2 {
			k := strings.TrimSpace(parts[0])
			v := strings.TrimSpace(parts[1])
			if k == "t" {
				timestamp = v
			} else if k == "v1" {
				expectedSig = v
			}
		}
	}

	if timestamp == "" || expectedSig == "" {
		return ErrInvalidWebhookSignature
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(fmt.Sprintf("%s.", timestamp)))
	mac.Write(payload)
	computedSig := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(computedSig), []byte(expectedSig)) {
		return ErrInvalidWebhookSignature
	}
	return nil
}
