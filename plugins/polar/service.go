package polar

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/BladiCreator/go-modular-auth/adapter"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
)

type service struct {
	ctx         *sdk.Context
	cfg         Config
	custRepo    *sdk.Repository[Customer]
	subRepo     *sdk.Repository[Subscription]
	benefitRepo *sdk.Repository[Benefit]
}

var _ Polar = (*service)(nil)

func newService(ctx *sdk.Context, cfg Config) *service {
	return &service{
		ctx:         ctx,
		cfg:         cfg,
		custRepo:    sdk.Model[Customer](ctx, ModelPolarCustomers),
		subRepo:     sdk.Model[Subscription](ctx, ModelPolarSubscriptions),
		benefitRepo: sdk.Model[Benefit](ctx, ModelPolarBenefits),
	}
}

// GetCustomer retrieves the Polar customer mapped to the target reference.
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

// CreateCustomer creates or registers a Polar customer mapping.
func (s *service) CreateCustomer(ctx context.Context, target TargetReference) (*Customer, error) {
	if target.ID == "" || target.Type == "" {
		return nil, ErrInvalidReference
	}

	existing, err := s.GetCustomer(ctx, target)
	if err == nil && existing != nil {
		return existing, nil
	}

	now := time.Now()
	id := fmt.Sprintf("pcust_%d", now.UnixNano())
	polarCustID := fmt.Sprintf("pol_cus_%s_%s", target.Type, target.ID)

	cust := &Customer{
		ID:              id,
		ReferenceID:     target.ID,
		ReferenceType:   target.Type,
		PolarCustomerID: polarCustID,
		Email:           fmt.Sprintf("%s@example.com", target.ID),
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	if err := s.custRepo.Create(ctx, cust); err != nil {
		return nil, err
	}
	return cust, nil
}

// CreateCheckout generates a Polar checkout session URL.
func (s *service) CreateCheckout(ctx context.Context, in CreateCheckoutInput) (*CheckoutResult, error) {
	if in.Target.ID == "" || in.ProductID == "" {
		return nil, ErrInvalidReference
	}

	checkoutID := fmt.Sprintf("chk_%d", time.Now().UnixNano())
	checkoutURL := fmt.Sprintf("%s/checkout/%s", s.cfg.ServerURL, checkoutID)

	return &CheckoutResult{
		CheckoutID: checkoutID,
		URL:        checkoutURL,
	}, nil
}

// GetCustomerPortalURL generates a URL to the Polar customer billing portal.
func (s *service) GetCustomerPortalURL(ctx context.Context, target TargetReference) (string, error) {
	cust, err := s.GetCustomer(ctx, target)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s/portal?customer_id=%s", s.cfg.ServerURL, cust.PolarCustomerID), nil
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

// HasActiveSubscription reports whether the target has an active subscription.
func (s *service) HasActiveSubscription(ctx context.Context, target TargetReference, productIDs ...string) (bool, error) {
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

	if len(productIDs) == 0 {
		return true, nil
	}

	for _, pid := range productIDs {
		if sub.PolarProductID == pid {
			return true, nil
		}
	}
	return false, nil
}

// HasBenefit reports whether the target identity has been granted a specific benefit.
func (s *service) HasBenefit(ctx context.Context, target TargetReference, benefitID string) (bool, error) {
	if target.ID == "" || benefitID == "" {
		return false, ErrInvalidReference
	}

	ben, err := s.benefitRepo.FindOne(ctx,
		adapter.Eq("reference_id", target.ID),
		adapter.Eq("polar_benefit_id", benefitID),
		adapter.Eq("is_granted", true),
	)
	if err != nil {
		if errors.Is(err, adapter.ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	return ben != nil && ben.IsGranted, nil
}

// ListBenefits lists all benefits currently granted to the target identity.
func (s *service) ListBenefits(ctx context.Context, target TargetReference) ([]Benefit, error) {
	if target.ID == "" {
		return nil, ErrInvalidReference
	}

	return s.benefitRepo.FindMany(ctx, adapter.Query{
		Where: []adapter.Condition{
			adapter.Eq("reference_id", target.ID),
			adapter.Eq("is_granted", true),
		},
	})
}

// HandleWebhook processes an incoming Polar webhook payload.
func (s *service) HandleWebhook(ctx context.Context, payload []byte, signature string) (*WebhookEvent, error) {
	if len(payload) == 0 {
		return nil, ErrInvalidPayload
	}

	if s.cfg.WebhookSecret != "" {
		if err := verifyPolarSignature(payload, signature, s.cfg.WebhookSecret); err != nil {
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

func verifyPolarSignature(payload []byte, signature string, secret string) error {
	if signature == "" {
		return ErrInvalidWebhookSignature
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	computedSig := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(computedSig), []byte(signature)) {
		return ErrInvalidWebhookSignature
	}
	return nil
}
