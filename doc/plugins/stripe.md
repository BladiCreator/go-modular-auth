# GoModularAuth Stripe Billing Plugin

`gomodularauth-stripe` provides enterprise subscription billing, customer provisioning, checkout sessions, customer portal sessions, and webhook synchronization with [Stripe](https://stripe.com) for **GoModularAuth**.

---

## 1. Problem Solved

Modern web applications require robust subscription management, credit card payments, seat-based billing, and self-service cancellation/upgrades. Implementing this without deep architectural coupling leads to:
- Tight coupling between payment webhooks and core authentication code.
- Inconsistent mapping between Stripe Customers and local User or Organization records.
- Brittle subscription checks littered across business logic.

`gomodularauth-stripe` decouples Stripe operations into a strongly typed capability while persisting customer and subscription records directly inside GoModularAuth's database adapter.

---

## 2. Features

- **Polymorphic Billing Targets**: Maps Stripe customer accounts to either individual users (`ReferenceUser`) or multi-tenant organizations (`ReferenceOrganization`).
- **Checkout Sessions**: Create hosted Stripe Checkout sessions with support for subscription price IDs, seat counts, and custom metadata.
- **Customer Billing Portal**: Issue single-sign-on sessions to Stripe's Customer Portal for payment method updates and subscription cancellations.
- **Deterministic Subscription Checks**: Fast local evaluation of active subscriptions via `HasActiveSubscription` without querying external Stripe APIs in hot paths.
- **Webhook Processing**: Validates HMAC SHA-256 signatures (`whsec_...`) and automatically maintains customer and subscription states.

---

## 3. Installation

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/stripe
```

---

## 4. Configuration & Registration

Register `stripe.New()` in GoModularAuth:

```go
package main

import (
    "log"

    auth "github.com/BladiCreator/go-modular-auth"
    "github.com/BladiCreator/go-modular-auth/adapters/memory"
    "github.com/BladiCreator/go-modular-auth/plugins/stripe"
)

func main() {
    ad := memory.NewAdapter()

    stripeModule := stripe.New(
        stripe.WithAPIKey("sk_test_..."),
        stripe.WithWebhookSecret("whsec_..."),
        stripe.WithAutoCreateCustomerOnSignUp(true),
        stripe.WithAutoCreateCustomerOnOrgCreation(true),
    )

    engine, err := auth.New(auth.Config{
        Adapter: ad,
        Plugins: []auth.PluginModule{stripeModule},
    })
    if err != nil {
        log.Fatalf("failed to initialize auth: %v", err)
    }

    // Resolve typed capability
    billing, err := auth.Get[stripe.Stripe](engine)
    if err != nil {
        log.Fatalf("failed to resolve Stripe capability: %v", err)
    }

    _ = billing
}
```

---

## 5. Primary Capability API

The capability is exposed via `stripe.Stripe`:

```go
type Stripe interface {
    GetCustomer(ctx context.Context, target TargetReference) (*Customer, error)
    CreateCustomer(ctx context.Context, target TargetReference) (*Customer, error)
    CreateCheckoutSession(ctx context.Context, in CreateCheckoutInput) (*CheckoutSession, error)
    CreateBillingPortalSession(ctx context.Context, target TargetReference, returnURL string) (*BillingPortalSession, error)
    GetActiveSubscription(ctx context.Context, target TargetReference) (*Subscription, error)
    HasActiveSubscription(ctx context.Context, target TargetReference, priceIDs ...string) (bool, error)
    HandleWebhook(ctx context.Context, payload []byte, signature string) (*WebhookEvent, error)
}
```

---

## 6. Usage Examples

### 6.1 Creating a Hosted Checkout Session

```go
session, err := billing.CreateCheckoutSession(ctx, stripe.CreateCheckoutInput{
    Target: stripe.TargetReference{
        Type: stripe.ReferenceUser,
        ID:   "usr_12345",
    },
    PriceID:    "price_enterprise_monthly",
    Quantity:   1,
    SuccessURL: "https://example.com/billing/success?session_id={CHECKOUT_SESSION_ID}",
    CancelURL:  "https://example.com/billing/cancel",
})
if err != nil {
    log.Fatal(err)
}

// Redirect client to session.URL
log.Printf("Stripe Checkout URL: %s", session.URL)
```

### 6.2 Accessing the Customer Billing Portal

```go
target := stripe.TargetReference{
    Type: stripe.ReferenceOrganization,
    ID:   "org_987",
}

portal, err := billing.CreateBillingPortalSession(ctx, target, "https://example.com/dashboard")
if err != nil {
    log.Fatal(err)
}

// Redirect user to portal.URL
log.Printf("Portal URL: %s", portal.URL)
```

### 6.3 Verifying Active Subscriptions

```go
target := stripe.TargetReference{
    Type: stripe.ReferenceUser,
    ID:   "usr_12345",
}

// Check if user has ANY active subscription
hasAnySub, err := billing.HasActiveSubscription(ctx, target)

// Check if user has specific price ID
hasPro, err := billing.HasActiveSubscription(ctx, target, "price_pro_monthly")
```

### 6.4 Handling Webhooks

```go
event, err := billing.HandleWebhook(ctx, requestBody, signatureHeader)
if err != nil {
    log.Printf("webhook verification failed: %v", err)
    return
}

log.Printf("Stripe event processed: %s", event.Type)
```
