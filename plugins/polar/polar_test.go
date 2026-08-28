package polar_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/plugins/polar"
)

func TestPolarPlugin_Initialization(t *testing.T) {
	repo := polar.NewMemoryRepository()
	p, err := polar.New(repo,
		polar.WithAccessToken("polar_token_123"),
		polar.WithWebhookSecret("whsec_test_secret"),
		polar.WithServer("sandbox"),
	)

	if err != nil {
		t.Fatalf("expected no error creating plugin, got %v", err)
	}

	if p.ID() != "polar" {
		t.Errorf("expected plugin ID 'polar', got %s", p.ID())
	}

	cfg := p.Config()
	if cfg.AccessToken != "polar_token_123" {
		t.Errorf("expected access token 'polar_token_123', got %s", cfg.AccessToken)
	}
	if cfg.WebhookSecret != "whsec_test_secret" {
		t.Errorf("expected webhook secret 'whsec_test_secret', got %s", cfg.WebhookSecret)
	}
}

func TestPolarPlugin_UserCreatedHook(t *testing.T) {
	repo := polar.NewMemoryRepository()
	p, err := polar.New(repo, polar.WithAccessToken("test_token"))
	if err != nil {
		t.Fatalf("failed to create plugin: %v", err)
	}

	ctx := context.Background()
	user := &entity.User{
		ID:    "user_123",
		Name:  "Test Gopher",
		Email: "gopher@example.com",
	}

	err = p.OnUserCreated(ctx, user)
	if err != nil {
		t.Fatalf("expected no error on user created hook, got %v", err)
	}

	custID, err := repo.GetCustomerPolarID(ctx, "user", "user_123")
	if err != nil || custID == "" {
		t.Fatalf("expected customer ID to be saved in repository, got %v, error: %v", custID, err)
	}
}

func TestPolarPlugin_CheckoutAndPortal(t *testing.T) {
	repo := polar.NewMemoryRepository()
	p, err := polar.New(repo,
		polar.WithAccessToken("test_token"),
		polar.WithPlans(polar.PolarPlan{
			ID:        "pro_plan",
			Name:      "Pro Plan",
			ProductID: "prod_pro",
			PriceID:   "price_pro_123",
		}),
	)
	if err != nil {
		t.Fatalf("failed to create plugin: %v", err)
	}

	ctx := context.Background()
	_ = repo.SaveCustomerPolarID(ctx, "user", "user_123", "pol_cust_123")

	url, err := p.CreateCheckoutSession(ctx, polar.CreateCheckoutParams{
		ProductPriceID: "price_pro_123",
		SuccessURL:     "https://app.example.com/success",
		ReferenceID:    "user_123",
	})

	if err != nil {
		t.Fatalf("expected no error creating checkout, got %v", err)
	}
	if url == "" {
		t.Error("expected non-empty checkout URL")
	}

	portalURL, err := p.CreateCustomerPortalSession(ctx, polar.CustomerPortalParams{
		ReferenceID: "user_123",
	})
	if err != nil {
		t.Fatalf("expected no error creating customer portal, got %v", err)
	}
	if portalURL == "" {
		t.Error("expected non-empty portal URL")
	}
}

func TestPolarPlugin_Webhooks(t *testing.T) {
	repo := polar.NewMemoryRepository()
	secret := "whsec_mysecretkey"

	var createdSub *polar.Subscription
	p, err := polar.New(repo,
		polar.WithWebhookSecret(secret),
		polar.WithOnSubscriptionCreated(func(ctx context.Context, sub *polar.Subscription) error {
			createdSub = sub
			return nil
		}),
	)
	if err != nil {
		t.Fatalf("failed to create plugin: %v", err)
	}

	rawPayload := []byte(`{
		"id": "evt_123",
		"type": "subscription.created",
		"data": {
			"id": "sub_pol_999",
			"customer_id": "pol_cust_123",
			"customer_external_id": "user_123",
			"product_id": "prod_pro",
			"price_id": "price_123",
			"status": "active",
			"amount": 2900,
			"currency": "usd",
			"recurring_interval": "month"
		}
	}`)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(rawPayload)
	sig := hex.EncodeToString(mac.Sum(nil))

	req := httptest.NewRequest(http.MethodPost, "/polar/webhooks", bytes.NewReader(rawPayload))
	req.Header.Set("webhook-signature", sig)
	rec := httptest.NewRecorder()

	p.HandleWebhook(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d. body: %s", rec.Code, rec.Body.String())
	}

	if createdSub == nil {
		t.Fatal("expected OnSubscriptionCreated callback to be triggered")
	}
	if createdSub.PolarSubscriptionID != "sub_pol_999" {
		t.Errorf("expected subscription ID sub_pol_999, got %s", createdSub.PolarSubscriptionID)
	}

	subs, err := p.ListSubscriptions(context.Background(), "user_123")
	if err != nil || len(subs) == 0 {
		t.Fatalf("expected subscription to be saved in repository")
	}
}

func TestPolarPlugin_Middleware(t *testing.T) {
	repo := polar.NewMemoryRepository()
	p, err := polar.New(repo)
	if err != nil {
		t.Fatalf("failed to create plugin: %v", err)
	}

	ctx := context.Background()
	_ = repo.CreateSubscription(ctx, &polar.Subscription{
		ID:                  "sub_1",
		PolarSubscriptionID: "sub_pol_1",
		ReferenceID:         "user_pro",
		Plan:                "pro_plan",
		Status:              "active",
	})

	handler := p.RequireActiveSubscription("pro_plan")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sub, ok := polar.SubscriptionFromContext(r.Context())
		if !ok || sub == nil {
			t.Error("expected subscription in context")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))

	// Test authorized request
	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.Header.Set("X-Reference-ID", "user_pro")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", rec.Code)
	}

	// Test unauthorized request (no active subscription)
	req2 := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req2.Header.Set("X-Reference-ID", "user_free")
	rec2 := httptest.NewRecorder()

	handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusPaymentRequired {
		t.Errorf("expected 402 Payment Required, got %d", rec2.Code)
	}
}
