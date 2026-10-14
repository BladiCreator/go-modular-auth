package polar_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	auth "github.com/BladiCreator/go-modular-auth"
	polar "github.com/BladiCreator/go-modular-auth/plugins/polar"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapter/memory"
)

func setupPolarApp(t *testing.T) (*auth.Auth, polar.Polar) {
	t.Helper()

	polarModule := polar.New(
		polar.WithAccessToken("polar_at_test_12345"),
		polar.WithWebhookSecret("polar_whsec_secret_123"),
	)

	engine, err := auth.New(auth.Config{
		Adapter: adaptermem.New(),
		Plugins: []auth.PluginModule{polarModule},
	})
	if err != nil {
		t.Fatalf("auth.New failed: %v", err)
	}

	cap, err := auth.Get[polar.Polar](engine)
	if err != nil {
		t.Fatalf("auth.Get[polar.Polar] failed: %v", err)
	}

	return engine, cap
}

func TestPolarCustomerAndCheckout(t *testing.T) {
	ctx := context.Background()
	_, client := setupPolarApp(t)

	orgTarget := polar.TargetReference{
		Type: polar.ReferenceOrganization,
		ID:   "org_xyz789",
	}

	// 1. Customer Creation
	cust, err := client.CreateCustomer(ctx, orgTarget)
	if err != nil {
		t.Fatalf("CreateCustomer failed: %v", err)
	}
	if cust.ReferenceID != orgTarget.ID || cust.ReferenceType != polar.ReferenceOrganization {
		t.Errorf("unexpected customer data: %+v", cust)
	}

	// 2. Customer Retrieval
	fetched, err := client.GetCustomer(ctx, orgTarget)
	if err != nil {
		t.Fatalf("GetCustomer failed: %v", err)
	}
	if fetched.ID != cust.ID {
		t.Errorf("expected customer ID %s, got %s", cust.ID, fetched.ID)
	}

	// 3. Checkout Creation
	checkout, err := client.CreateCheckout(ctx, polar.CreateCheckoutInput{
		Target:    orgTarget,
		ProductID: "prod_pro_plan",
	})
	if err != nil {
		t.Fatalf("CreateCheckout failed: %v", err)
	}
	if checkout.CheckoutID == "" || checkout.URL == "" {
		t.Errorf("empty checkout result: %+v", checkout)
	}

	// 4. Portal URL
	portalURL, err := client.GetCustomerPortalURL(ctx, orgTarget)
	if err != nil {
		t.Fatalf("GetCustomerPortalURL failed: %v", err)
	}
	if portalURL == "" {
		t.Errorf("empty portal url")
	}
}

func TestPolarWebhookVerification(t *testing.T) {
	ctx := context.Background()
	_, client := setupPolarApp(t)

	secret := "polar_whsec_secret_123"
	payload := []byte(`{"id":"evt_polar_1","type":"subscription.created"}`)

	// Compute valid HMAC SHA-256
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	validSig := hex.EncodeToString(mac.Sum(nil))

	// Valid webhook
	evt, err := client.HandleWebhook(ctx, payload, validSig)
	if err != nil {
		t.Fatalf("HandleWebhook failed with valid signature: %v", err)
	}
	if evt.ID != "evt_polar_1" || evt.Type != "subscription.created" {
		t.Errorf("unexpected event: %+v", evt)
	}

	// Invalid signature
	_, err = client.HandleWebhook(ctx, payload, "invalid_sig_hex")
	if err == nil {
		t.Fatal("expected error on invalid signature, got nil")
	}
}
