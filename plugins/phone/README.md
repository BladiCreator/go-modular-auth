# gomodularauth-phone

[![Go Reference](https://pkg.go.dev/badge/github.com/BladiCreator/go-modular-auth/plugins/phone.svg)](https://pkg.go.dev/github.com/BladiCreator/go-modular-auth/plugins/phone)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

`gomodularauth-phone` is an official plugin module for **[GoModularAuth](https://github.com/BladiCreator/go-modular-auth)**. It provides first-class phone-number identity mappings and single-use phone OTP (One-Time Password) authentication through a provider-agnostic server-side interface.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Provider Abstraction](#provider-abstraction)
- [Public API](#public-api)
  - [Phone Capability](#phone-capability)
  - [Authentication Flow](#authentication-flow)
  - [Verification Flow](#verification-flow)
  - [Change and Removal Flows](#change-and-removal-flows)
- [Persistence & Migrations](#persistence--migrations)
- [Cache & Rate Limiting](#cache--rate-limiting)
- [Events](#events)
- [Hooks](#hooks)
- [Security Model](#security-model)
- [Testing](#testing)

---

## Features

- **Provider-Agnostic Interface**: Define an explicit `PhoneProvider` abstraction. Easily plug in Twilio, Vonage, AWS SNS, Infobip, or internal gateways without vendor lock-in.
- **E.164 Phone Normalization**: Robust parsing and canonical normalization following ITU-T E.164 standards (+[country_code][subscriber_number]).
- **Phone OTP Authentication**: Complete passwordless sign-in and sign-up flows with single-use, salted, cryptographically hashed tokens.
- **Enumeration Protection**: Constant-time response and silent no-op handling when unregistered phone numbers request verification under restricted sign-up policies.
- **Brute-Force & Attempt Protection**: Configurable attempt thresholds (`MaxAttempts`) that permanently lock compromised OTPs, with rate limiting and cooldown periods.
- **Phone Verification, Change & Removal**: Verification ceremonies for existing users, atomic phone updates with uniqueness guarantees, and clean unlinking.
- **Transactional Consistency**: Adheres to Core `VerificationToken` semantics, treating the Store as the single source of truth while utilizing the Cache purely for acceleration and rate limiting.
- **Event-Driven**: Emits rich domain events (`phone.otp.requested`, `phone.otp.verified`, `phone.verified`, `phone.changed`, `phone.removed`) without ever leaking secrets or plaintext tokens.

---

## Architecture

`gomodularauth-phone` strictly obeys GoModularAuth's modular dependency topology:

```text
Application
    ↓
GoModularAuth Core (auth.Auth)
    ↓
gomodularauth-phone (PluginModule)
    ↓
Phone Capability (plugins.Phone)
```

The plugin depends on the Core; the Core has zero compile-time knowledge of this plugin. The plugin can be omitted or installed dynamically at runtime.

---

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/phone
```

---

## Quick Start

```go
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/BladiCreator/go-modular-auth/auth"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapter/memory"
	phone "github.com/BladiCreator/go-modular-auth/plugins/phone"
	"github.com/BladiCreator/go-modular-auth/plugins/phone/plugins"
)

// Example Twilio or custom SMS provider
type CustomSMSProvider struct{}

func (s *CustomSMSProvider) Send(ctx context.Context, msg phone.Message) error {
	fmt.Printf("[SMS Gateway] Sending SMS to %s: %s\n", msg.To, msg.Body)
	return nil
}

func main() {
	smsProvider := &CustomSMSProvider{}

	// 1. Initialize GoModularAuth engine with the Phone plugin
	engine, err := auth.New(auth.Config{
		Adapter: adaptermem.New(),
		Plugins: []auth.PluginModule{
			phone.New(
				phone.WithProvider(smsProvider),
				phone.WithTTL(5*time.Minute),
				phone.WithMaxAttempts(3),
				phone.WithAllowSignUp(true),
			),
		},
	})
	if err != nil {
		log.Fatalf("failed to initialize auth: %v", err)
	}

	// 2. Retrieve the strongly typed Phone capability
	phoneAuth, err := auth.Get[plugins.Phone](engine)
	if err != nil {
		log.Fatalf("failed to get phone capability: %v", err)
	}

	ctx := context.Background()

	// 3. Request an OTP
	err = phoneAuth.RequestOTP(ctx, phone.RequestOTPInput{
		PhoneNumber: "+1 (202) 555-0123",
	})
	if err != nil {
		log.Fatalf("RequestOTP failed: %v", err)
	}

	// 4. Verify the OTP code received by the user
	res, err := phoneAuth.VerifyOTP(ctx, phone.VerifyOTPInput{
		PhoneNumber: "+12025550123",
		Code:        "123456", // code delivered via SMS
	})
	if err != nil {
		log.Fatalf("VerifyOTP failed: %v", err)
	}

	fmt.Printf("Authenticated successfully! User ID: %s, Session Token: %s\n", res.User.ID, res.Token)
}
```

---

## Configuration

The plugin is configured using functional options passed to `phone.New()`:

| Option | Description | Default |
|---|---|---|
| `WithProvider(p PhoneProvider)` | Sets the SMS/voice message delivery provider. | Required |
| `WithTTL(d time.Duration)` | Sets the validity duration of issued OTP codes. | `5 minutes` |
| `WithOTPLength(n int)` | Numeric digit length of generated OTP codes (4-12). | `6` |
| `WithMaxAttempts(n int)` | Maximum failed verification attempts before permanent token lockout. | `3` |
| `WithAllowSignUp(b bool)` | If true, auto-provisions accounts for new phone numbers upon first verification. | `true` |
| `WithRevokePreviousOnRequest(b bool)` | Automatically invalidates active pending OTPs before issuing a new code. | `true` |
| `WithRateLimit(max, window, cooldown)` | Configures rate limiting and cooldown intervals. | Disabled |
| `WithCacheFailurePolicy(policy)` | Configures `FailOpen` or `FailClosed` policy on cache errors. | `FailOpen` |
| `WithCacheTTL(d time.Duration)` | Sets TTL for ephemeral phone lookups. | `15 minutes` |
| `WithNormalizer(n Normalizer)` | Overrides standard E.164 normalization function. | ITU-T E.164 normalizer |
| `WithValidator(v Validator)` | Overrides canonical phone validation function. | ITU-T E.164 validator |
| `WithMessageBuilder(mb MessageBuilder)` | Customizes SMS body and delivery copy. | `DefaultMessageBuilder` |
| `WithHooks(h *Hooks)` | Injects workflow lifecycle interception hooks. | Empty registry |

---

## Provider Abstraction

`gomodularauth-phone` never imports vendor-specific SDKs. Delivery is abstracted through `PhoneProvider`:

```go
type Message struct {
    To       string            // E.164 recipient phone number
    Body     string            // Formatted message text
    Code     string            // Raw verification code
    Purpose  string            // "phone:authenticate", "phone:verify", "phone:change"
    TTL      time.Duration     // Token expiration duration
    Metadata map[string]string // Custom context or vendor options
}

type PhoneProvider interface {
    Send(ctx context.Context, msg Message) error
}
```

For unit and integration testing, the plugin includes `NewMockProvider()`:

```go
mock := phone.NewMockProvider()
// Inspect sent messages:
last := mock.LastMessage()
fmt.Println(last.Code)
```

---

## Public API

Applications access the plugin capability through:

```go
phoneService, err := auth.Get[plugins.Phone](a)
```

### Phone Capability Interface

```go
type Phone interface {
    RequestOTP(ctx context.Context, in RequestOTPInput) error
    VerifyOTP(ctx context.Context, in VerifyOTPInput) (*auth.AuthResult, error)

    RequestVerification(ctx context.Context, in RequestVerificationInput) error
    ConfirmVerification(ctx context.Context, in ConfirmVerificationInput) (*Record, error)

    RequestChange(ctx context.Context, in RequestChangeInput) error
    ConfirmChange(ctx context.Context, in ConfirmChangeInput) (*Record, error)

    Remove(ctx context.Context, in RemoveInput) error

    GetByUserID(ctx context.Context, userID string) (*Record, error)
    GetByPhone(ctx context.Context, phoneNumber string) (*Record, error)

    Normalize(raw string) (string, error)
    Validate(normalized string) error
}
```

---

## Persistence & Migrations

The plugin defines a clean domain persistence contract:

```go
type Store interface {
    CreatePhone(ctx context.Context, p *PhoneRecord) error
    GetPhoneByUserID(ctx context.Context, userID string) (*PhoneRecord, error)
    GetPhoneByNumber(ctx context.Context, phoneNumber string) (*PhoneRecord, error)
    UpdatePhone(ctx context.Context, p *PhoneRecord) error
    DeletePhone(ctx context.Context, userID string) error

    CreateOTP(ctx context.Context, o *OTPRecord) error
    GetActiveOTP(ctx context.Context, phoneNumber, purpose string, now time.Time) (*OTPRecord, error)
    IncrementOTPAttempts(ctx context.Context, id string) (int, error)
    MarkOTPUsed(ctx context.Context, id string, at time.Time) error
    RevokeOTPsByPhone(ctx context.Context, phoneNumber, purpose string) error
    DeleteExpiredOTPs(ctx context.Context, before time.Time) (int, error)
}
```

### PostgreSQL

A production adapter is provided in `store/postgres`, with migration schema in `migrations/001_create_phone_tables.sql`:

```sql
CREATE TABLE IF NOT EXISTS phones (
    id VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL,
    phone_number VARCHAR(32) NOT NULL,
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    verified_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT uq_phones_user_id UNIQUE (user_id),
    CONSTRAINT uq_phones_phone_number UNIQUE (phone_number)
);

CREATE TABLE IF NOT EXISTS phone_otps (
    id VARCHAR(64) PRIMARY KEY,
    phone_number VARCHAR(32) NOT NULL,
    subject VARCHAR(64) NOT NULL,
    purpose VARCHAR(64) NOT NULL,
    otp_hash VARCHAR(128) NOT NULL,
    salt VARCHAR(64) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    max_attempts INT NOT NULL DEFAULT 3,
    attempts INT NOT NULL DEFAULT 0,
    used_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL
);
```

---

## Cache & Rate Limiting

The Store is the authoritative source of truth. The Cache is used exclusively for rate limiting, cooldown tracking, and ephemeral lookup acceleration:

- **Namespace Isolation**: Keys are prefixed with `gomodularauth:phone:...`.
- **PII Protection**: Plaintext phone numbers are never stored in cache keys. Keys use SHA-256 digests (`HashIdentifier`).
- **Cache Invalidation**: Updating or deleting a phone record immediately purges the corresponding cache keys.

---

## Events

The plugin emits domain events through the Core event dispatcher:

- `phone.otp.requested`: An OTP code was generated and dispatched.
- `phone.otp.verified`: An OTP was validated and authenticated.
- `phone.otp.rejected`: An OTP verification failed (expired, locked, or invalid).
- `phone.verified`: A phone number was validated and confirmed for a user.
- `phone.changed`: A user updated their phone number.
- `phone.removed`: A user disassociated their phone number.

> **Security Guarantee**: Event payloads strictly omit raw OTP codes, token hashes, and salts.

---

## Hooks

Intercept workflows to enforce custom business rules:

```go
hooks := phone.NewHooks()
hooks.BeforeRequestOTP(func(ctx context.Context, in *phone.RequestOTPInput) error {
    log.Printf("OTP requested for %s", in.PhoneNumber)
    return nil
})
```

---

## Security Model

1. **Entropy & Crypto**: Codes are generated using `crypto/rand` rejecting bytes >= 250 to prevent modulo bias.
2. **Salted Hashing**: Codes are hashed with unique 16-byte cryptographic salts (`SHA-256`). Plaintext codes are never stored in persistence or logs.
3. **Constant-Time Comparison**: Verification utilizes `crypto/subtle.ConstantTimeCompare` to mitigate timing side-channel attacks.
4. **Single-Use Semantics**: `MarkOTPUsed` executes an atomic conditional update (`WHERE used_at IS NULL AND attempts < max_attempts`), preventing replay and double-redemption races.
5. **Enumeration Protection**: When `AllowSignUp` is disabled, requesting verification for unknown numbers returns `nil` without sending SMS, preventing attacker enumeration.

---

## Testing

Run unit, integration, concurrency, and security suites:

```bash
go test -v -race ./...
```
