# GoModularAuth Polar Billing Plugin

`gomodularauth-polar` provides subscription billing, automated customer provisioning, customer portal sessions, and license benefit checks integrated with [Polar.sh](https://polar.sh) for **GoModularAuth**.

---

## 1. Problem Solved

Modern SaaS and developer-tool applications monetize via subscriptions, pay-per-seat tiers, and digital benefit/license key distribution. Handling billing requires:
- Linking customer identities in Polar to canonical `User` or `Organization` IDs.
- Generating checkout flows and self-service customer portal URLs.
- Gating features based on active subscriptions or license benefits.
- Transport-agnostic processing and signature verification of Polar webhooks.

`gomodularauth-polar` resolves these requirements while adhering to GoModularAuth's Hexagonal architecture and schema-driven database persistence.

---

## 2. Features

- **Polymorphic Billing Targets**: Maps Polar customers to either individual users (`ReferenceUser`) or multi-tenant organizations (`ReferenceOrganization`).
- **Subscription Verification**: Deterministic checks via `HasActiveSubscription` against specific product IDs or any active plan.
- **Benefit & License Gating**: Query whether an identity holds specific digital benefits via `HasBenefit` and `ListBenefits`.
- **Checkout & Portal Sessions**: Create checkout URLs and self-service customer portal links.
- **Webhook Processing**: Validates Standard Webhook signatures and synchronizes customer and subscription state automatically.
- **Unified Persistence**: Synchronizes customer mappings and subscriptions in the configured `adapter.Adapter` via `sdk.Model`.

---

## 3. Installation

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/polar
```

---

## 4. Configuration & Registration

Register `polar.New()` into GoModularAuth:

```go
package main

import (
    "log"

    auth "github.com/BladiCreator/go-modular-auth"
    "github.com/BladiCreator/go-modular-auth/adapters/memory"
    "github.com/BladiCreator/go-modular-auth/plugins/polar"
)

func main() {
    ad := memory.NewAdapter()

    polarModule := polar.New(
        polar.WithAccessToken("polar_at_your_access_token"),
        polar.WithWebhookSecret("your_webhook_secret"),
        polar.WithAutoCreateCustomerOnSignUp(true),
        polar.WithAutoCreateCustomerOnOrgCreation(true),
    )

    engine, err := auth.New(auth.Config{
        Adapter: ad,
        Plugins: []auth.PluginModule{polarModule},
    })
    if err != nil {
        log.Fatalf("failed to initialize auth: %v", err)
    }

    // Resolve typed capability
    billing, err := auth.Get[polar.Polar](engine)
    if err != nil {
        log.Fatalf("failed to resolve Polar capability: %v", err)
    }

    _ = billing
}
```

---

## 5. Primary Capability API

The plugin exposes the `polar.Polar` interface:

```go
type Polar interface {
    GetCustomer(ctx context.Context, target TargetReference) (*Customer, error)
    CreateCustomer(ctx context.Context, target TargetReference) (*Customer, error)
    CreateCheckout(ctx context.Context, in CreateCheckoutInput) (*CheckoutResult, error)
    GetCustomerPortalURL(ctx context.Context, target TargetReference) (string, error)
    GetActiveSubscription(ctx context.Context, target TargetReference) (*Subscription, error)
    HasActiveSubscription(ctx context.Context, target TargetReference, productIDs ...string) (bool, error)
    HasBenefit(ctx context.Context, target TargetReference, benefitID string) (bool, error)
    ListBenefits(ctx context.Context, target TargetReference) ([]Benefit, error)
    HandleWebhook(ctx context.Context, payload []byte, signature string) (*WebhookEvent, error)
}
```

---

## 6. Usage Examples

### 6.1 Checking Active Subscriptions

```go
target := polar.TargetReference{
    Type: polar.ReferenceUser,
    ID:   "usr_12345",
}

hasSub, err := billing.HasActiveSubscription(ctx, target, "prod_pro_tier")
if err != nil {
    log.Printf("subscription check error: %v", err)
    return
}
if !hasSub {
    log.Println("user is not subscribed to pro tier")
}
```

### 6.2 Generating Checkout URL

```go
checkout, err := billing.CreateCheckout(ctx, polar.CreateCheckoutInput{
    Target: polar.TargetReference{
        Type: polar.ReferenceUser,
        ID:   "usr_12345",
    },
    ProductID:  "prod_pro_tier",
    SuccessURL: "https://example.com/billing/success",
})
if err != nil {
    log.Fatal(err)
}

// Redirect user to checkout.URL
log.Printf("Checkout URL: %s", checkout.URL)
```

### 6.3 Handling Incoming Webhooks

```go
event, err := billing.HandleWebhook(ctx, rawPayload, signatureHeader)
if err != nil {
    // Signature verification failure or parse error
    log.Printf("webhook error: %v", err)
    return
}
log.Printf("Processed Polar webhook event: %s", event.Type)
```
