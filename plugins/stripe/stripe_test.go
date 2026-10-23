package stripe_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapter/memory"
	stripe "github.com/BladiCreator/go-modular-auth/plugins/stripe"
)

func setupStripeApp(t *testing.T) (*auth.Auth, stripe.Stripe) {
	t.Helper()

	stripeModule := stripe.New(
		stripe.WithAPIKey("sk_test_12345"),
		stripe.WithWebhookSecret("whsec_test_secret_123"),
	)

	engine, err := auth.New(auth.Config{
		Adapter: adaptermem.New(),
		Plugins: []auth.PluginModule{stripeModule},
	})
	if err != nil {
		t.Fatalf("auth.New failed: %v", err)
	}

	cap, err := auth.Get[stripe.Stripe](engine)
	if err != nil {
		t.Fatalf("auth.Get[stripe.Stripe] failed: %v", err)
	}

	return engine, cap
}

func TestStripeCustomerAndSubscription(t *testing.T) {
	ctx := context.Background()
	_, client := setupStripeApp(t)

	userTarget := stripe.TargetReference{
		Type: stripe.ReferenceUser,
		ID:   "usr_abc123",
	}

	// 1. Customer Creation
	cust, err := client.CreateCustomer(ctx, userTarget)
	if err != nil {
		t.Fatalf("CreateCustomer failed: %v", err)
	}
	if cust.ReferenceID != userTarget.ID || cust.ReferenceType != stripe.ReferenceUser {
		t.Errorf("unexpected customer data: %+v", cust)
	}

	// 2. Customer Retrieval
	fetched, err := client.GetCustomer(ctx, userTarget)
	if err != nil {
		t.Fatalf("GetCustomer failed: %v", err)
	}
	if fetched.ID != cust.ID {
		t.Errorf("expected customer ID %s, got %s", cust.ID, fetched.ID)
	}

	// 3. Checkout Session
	checkout, err := client.CreateCheckoutSession(ctx, stripe.CreateCheckoutInput{
		Target:     userTarget,
		PriceID:    "price_pro_monthly",
		SuccessURL: "https://example.com/success",
		CancelURL:  "https://example.com/cancel",
	})
	if err != nil {
		t.Fatalf("CreateCheckoutSession failed: %v", err)
	}
	if checkout.SessionID == "" || checkout.URL == "" {
		t.Errorf("empty checkout response: %+v", checkout)
	}

	// 4. Billing Portal Session
	portal, err := client.CreateBillingPortalSession(ctx, userTarget, "https://example.com/dashboard")
	if err != nil {
		t.Fatalf("CreateBillingPortalSession failed: %v", err)
	}
	if portal.URL == "" {
		t.Errorf("empty portal url: %+v", portal)
	}
}

func TestStripeWebhookVerification(t *testing.T) {
	ctx := context.Background()
	_, client := setupStripeApp(t)

	secret := "whsec_test_secret_123"
	payload := []byte(`{"id":"evt_123","type":"customer.subscription.created"}`)
	timestamp := fmt.Sprintf("%d", time.Now().Unix())

	// Generate valid Stripe signature
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(fmt.Sprintf("%s.", timestamp)))
	mac.Write(payload)
	validSig := hex.EncodeToString(mac.Sum(nil))

	sigHeader := fmt.Sprintf("t=%s,v1=%s", timestamp, validSig)

	// Valid webhook
	evt, err := client.HandleWebhook(ctx, payload, sigHeader)
	if err != nil {
		t.Fatalf("HandleWebhook failed with valid signature: %v", err)
	}
	if evt.ID != "evt_123" || evt.Type != "customer.subscription.created" {
		t.Errorf("unexpected event: %+v", evt)
	}

	// Invalid signature
	badSigHeader := fmt.Sprintf("t=%s,v1=invalid_signature", timestamp)
	_, err = client.HandleWebhook(ctx, payload, badSigHeader)
	if err == nil {
		t.Fatal("expected error on invalid signature, got nil")
	}
}
