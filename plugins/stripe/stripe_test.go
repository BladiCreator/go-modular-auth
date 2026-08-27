package stripe_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth/plugin"
	"github.com/BladiCreator/go-modular-auth/plugins/stripe"
)

func TestNew_RequiresRepository(t *testing.T) {
	_, err := stripe.New(nil)
	if err == nil {
		t.Fatalf("expected error when repo is nil, got nil")
	}
}

func TestPlugin_IDAndInit(t *testing.T) {
	repo := stripe.NewMemoryRepository()
	p, err := stripe.New(repo,
		stripe.WithStripeAPIKey("sk_test_mock"),
		stripe.WithWebhookSecret("whsec_mock"),
		stripe.WithPlans(stripe.StripePlan{
			ID:      "pro_plan",
			Name:    "Pro Plan",
			PriceID: "price_pro_123",
		}),
	)
	if err != nil {
		t.Fatalf("unexpected error creating plugin: %v", err)
	}

	if p.ID() != stripe.PluginID {
		t.Errorf("expected ID %q, got %q", stripe.PluginID, p.ID())
	}

	ctx := &plugin.Context{}
	if err := p.Init(ctx); err != nil {
		t.Errorf("unexpected error initializing plugin: %v", err)
	}

	cfg := p.Config()
	if cfg.StripeAPIKey != "sk_test_mock" {
		t.Errorf("expected API key sk_test_mock, got %s", cfg.StripeAPIKey)
	}
}

func TestMemoryRepository_CRUD(t *testing.T) {
	repo := stripe.NewMemoryRepository()
	ctx := context.Background()

	sub := &stripe.Subscription{
		ID:                   "sub_123",
		Plan:                 "pro_plan",
		ReferenceID:          "ref_user_1",
		StripeCustomerID:     "cus_stripe_1",
		StripeSubscriptionID: "sub_stripe_1",
		Status:               stripe.StatusActive,
		PeriodStart:          time.Now(),
		PeriodEnd:            time.Now().Add(30 * 24 * time.Hour),
	}

	if err := repo.CreateSubscription(ctx, sub); err != nil {
		t.Fatalf("failed to create subscription: %v", err)
	}

	foundByID, err := repo.FindSubscriptionByID(ctx, "sub_123")
	if err != nil || foundByID.Plan != "pro_plan" {
		t.Fatalf("failed to find subscription by ID: %v", err)
	}

	foundByStripeID, err := repo.FindSubscriptionByStripeID(ctx, "sub_stripe_1")
	if err != nil || foundByStripeID.ID != "sub_123" {
		t.Fatalf("failed to find subscription by Stripe ID: %v", err)
	}

	list, err := repo.ListSubscriptionsByReferenceID(ctx, "ref_user_1")
	if err != nil || len(list) != 1 {
		t.Fatalf("expected 1 subscription for ref_user_1, got %d", len(list))
	}

	sub.Status = stripe.StatusCanceled
	if err := repo.UpdateSubscription(ctx, sub); err != nil {
		t.Fatalf("failed to update subscription: %v", err)
	}

	foundUpdated, _ := repo.FindSubscriptionByID(ctx, "sub_123")
	if foundUpdated.Status != stripe.StatusCanceled {
		t.Errorf("expected status canceled, got %s", foundUpdated.Status)
	}

	if err := repo.SaveCustomerStripeID(ctx, "user", "user_1", "cus_123"); err != nil {
		t.Fatalf("failed to save customer stripe ID: %v", err)
	}

	custID, err := repo.GetCustomerStripeID(ctx, "user", "user_1")
	if err != nil || custID != "cus_123" {
		t.Errorf("expected customer ID cus_123, got %s", custID)
	}
}

func TestUtilsAndMetadata(t *testing.T) {
	cfg := stripe.DefaultConfig()
	cfg.Subscription.Plans = []stripe.StripePlan{
		{ID: "basic", Name: "Basic", PriceID: "price_basic_1", LookupKey: "basic_monthly"},
		{ID: "pro", Name: "Pro", PriceID: "price_pro_2", LookupKey: "pro_monthly"},
	}

	plan, ok := stripe.GetPlanByID(cfg, "basic")
	if !ok || plan.Name != "Basic" {
		t.Errorf("failed to lookup plan by ID")
	}

	planByPrice, ok := stripe.GetPlanByPriceID(cfg, "price_pro_2")
	if !ok || planByPrice.ID != "pro" {
		t.Errorf("failed to lookup plan by PriceID")
	}

	planByLookup, ok := stripe.GetPlanByLookupKey(cfg, "basic_monthly")
	if !ok || planByLookup.ID != "basic" {
		t.Errorf("failed to lookup plan by LookupKey")
	}

	escaped := stripe.EscapeStripeSearchValue(`user's "test" \ key`)
	if escaped != `user\'s \"test\" \\ key` {
		t.Errorf("escaping mismatch: %s", escaped)
	}

	meta := stripe.BuildMetadata("ref_100", "user", map[string]string{"env": "prod"})
	if meta["referenceId"] != "ref_100" || meta["env"] != "prod" {
		t.Errorf("metadata build mismatch: %v", meta)
	}

	refID, entityType, ok := stripe.ExtractReferenceID(meta)
	if !ok || refID != "ref_100" || entityType != "user" {
		t.Errorf("metadata extraction mismatch: refID=%s, entityType=%s, ok=%v", refID, entityType, ok)
	}
}

func TestRequireActiveSubscriptionMiddleware(t *testing.T) {
	repo := stripe.NewMemoryRepository()
	ctx := context.Background()

	p, err := stripe.New(repo, stripe.WithPlans(stripe.StripePlan{ID: "pro", PriceID: "price_pro"}))
	if err != nil {
		t.Fatalf("failed to create plugin: %v", err)
	}

	// Case 1: No active subscription -> 402 Payment Required
	handler := p.RequireActiveSubscription("pro")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/protected?referenceId=ref_999", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusPaymentRequired {
		t.Errorf("expected 402 Payment Required when no subscription exists, got %d", rec.Code)
	}

	// Case 2: Create active subscription -> 200 OK
	_ = repo.CreateSubscription(ctx, &stripe.Subscription{
		ID:          "sub_999",
		Plan:        "pro",
		ReferenceID: "ref_999",
		Status:      stripe.StatusActive,
	})

	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req)

	if rec2.Code != http.StatusOK {
		t.Errorf("expected 200 OK with active subscription, got %d", rec2.Code)
	}
}
