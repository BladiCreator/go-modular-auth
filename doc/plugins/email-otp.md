# GoModularAuth Email OTP Plugin (`gomodularauth-email-otp`)

[![Go Reference](https://pkg.go.dev/badge/github.com/BladiCreator/go-modular-auth/plugins/email-otp.svg)](https://pkg.go.dev/github.com/BladiCreator/go-modular-auth/plugins/email-otp)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A production-ready, passwordless authentication plugin for **GoModularAuth** providing short-lived, single-use email One-Time Password (OTP) verification codes.

---

## Table of Contents

- [1. Overview](#1-overview)
- [2. Architecture](#2-architecture)
- [3. Installation](#3-installation)
- [4. Quick Start](#4-quick-start)
- [5. Configuration Options](#5-configuration-options)
- [6. Public Capability Interface](#6-public-capability-interface)
- [7. Security Architecture](#7-security-architecture)
- [8. Database Migrations](#8-database-migrations)
- [9. Observability & Events](#9-observability--events)
- [10. License](#10-license)

---

## 1. Overview

`gomodularauth-email-otp` implements passwordless authentication using short-lived numeric OTP codes dispatched via email. It adheres strictly to GoModularAuth's architectural principles:
- **Core VerificationToken Semantics**: Extends token semantics with single-use guarantees, expiration checks, and atomic state consumption.
- **Cryptographic Security**: Codes are generated using `crypto/rand` without modulo bias and are never stored in plaintext. Persisted hashes use salted SHA-256 with constant-time verification.
- **Brute-Force & Replay Protection**: Enforces configurable maximum verification attempts with permanent lockout upon exceeding limits.
- **User Enumeration Defense**: Requests for unregistered emails return a silent success when sign-up is disabled, preventing identity probing.
- **Fail-Open / Fail-Closed Cache Policies**: Explicitly configurable behavior when distributed cache adapters encounter outages.
- **Zero Infrastructure Coupling**: Depends only on GoModularAuth Core contracts (`store.Store`, `email.Sender`, `cache.Cache`). Never couples to SMTP or concrete database drivers.

---

## 2. Architecture

```text
       Application (HTTP / CLI / gRPC)
                     │
                     ▼
             GoModularAuth Core
                     │
       ┌─────────────┴─────────────┐
       ▼                           ▼
Email OTP Plugin           Store Adapter
(auth.Get[EmailOTP]())     (PostgreSQL / Memory)
       │                           ▲
       ├─► Email Sender (SES / SMTP adapter)
       │                           │
       └─► Cache Adapter (Redis / Memory)
```

---

## 3. Installation

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/email-otp
```

---

## 4. Quick Start

```go
package main

import (
	"context"
	"log"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapters/memory"
	emailotp "github.com/BladiCreator/go-modular-auth/plugins/email-otp"
	"github.com/BladiCreator/go-modular-auth/plugins/email-otp/plugins"
)

func main() {
	ctx := context.Background()

	// Initialize GoModularAuth with Email OTP plugin
	engine, err := auth.New(auth.Config{
		Adapter: adaptermem.NewAdapter(),
		Email:   adaptermem.NewEmail(),
		Plugins: []auth.PluginModule{
			emailotp.New(
				emailotp.WithOTPLength(6),
				emailotp.WithTTL(10 * time.Minute),
				emailotp.WithMaxAttempts(3),
				emailotp.WithAllowSignUp(true),
			),
		},
	})
	if err != nil {
		log.Fatalf("failed to initialize auth: %v", err)
	}

	// Retrieve typed Capability via GoModularAuth
	otpAuth, err := auth.Get[plugins.EmailOTP](engine)
	if err != nil {
		log.Fatalf("failed to resolve capability: %v", err)
	}

	// 1. Request OTP
	err = otpAuth.Request(ctx, emailotp.RequestInput{
		Email: "user@example.com",
	})
	if err != nil {
		log.Fatalf("request failed: %v", err)
	}

	// 2. Verify OTP (code delivered to user's inbox)
	result, err := otpAuth.Verify(ctx, emailotp.VerifyInput{
		Email: "user@example.com",
		Code:  "123456",
	})
	if err != nil {
		log.Fatalf("verification failed: %v", err)
	}

	log.Printf("Authenticated user ID: %s, Session ID: %s", result.User.ID, result.Session.ID)
}
```

---

## 5. Configuration Options

| Option | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `WithEmailSender(email.Sender)` | `email.Sender` | Host's email sender | Email delivery adapter. |
| `WithTTL(time.Duration)` | `time.Duration` | `10m` | Validity window for issued OTP codes. |
| `WithOTPLength(int)` | `int` | `6` | Length of numeric code (between 4 and 12). |
| `WithMaxAttempts(int)` | `int` | `3` | Maximum failed verification attempts before lockout. |
| `WithAllowSignUp(bool)` | `bool` | `true` | Allows creating new accounts on successful verification. |
| `WithRevokePreviousOnRequest(bool)` | `bool` | `true` | Revokes older active OTPs upon new code dispatch. |
| `WithRateLimit(max, window, cooldown)` | `int, time.Duration` | Disabled | Configures request throttling and cooldowns. |
| `WithCacheFailurePolicy(policy)` | `cache.FailurePolicy` | `FailOpen` | Policy (`FailOpen` or `FailClosed`) for cache errors. |
| `WithMessageBuilder(builder)` | `MessageBuilder` | Default template | Customizes the delivered email subject and body. |
| `WithHooks(hooks)` | `*Hooks` | Empty | Workflow hooks for synchronous interception. |

---

## 6. Public Capability Interface

```go
type EmailOTP interface {
    // Request generates and delivers an OTP to the given email address.
    // When AllowSignUp is false and email is unknown, returns nil to prevent user enumeration.
    Request(ctx context.Context, in RequestInput) error

    // Verify atomically consumes the OTP and establishes an authenticated session.
    Verify(ctx context.Context, in VerifyInput) (*auth.AuthResult, error)

    // Revoke deletes or invalidates all active OTPs for the email address.
    Revoke(ctx context.Context, email string) error
}
```

---

## 7. Security Architecture

1. **Storage Security**:
   - Plaintext OTP values are **never** persisted or logged.
   - Every record stores a salted SHA-256 hash (`salt:code`) with a 128-bit random cryptographic salt.
   - Rainbow tables are completely neutralized.
2. **Atomic Verification**:
   - Verification and consumption are atomic (`MarkUsed` conditional update).
   - Prevents double-consumption and concurrent race conditions.
3. **Attempt Limiting**:
   - Failed attempts are tracked authoritatively in the store.
   - Exceeding `MaxAttempts` permanently locks the OTP, stopping brute-force attacks.
4. **User Enumeration**:
   - When `AllowSignUp` is disabled, non-existent emails return `nil` without sending emails.
5. **Replay Prevention**:
   - Single-use semantics guarantee that consumed tokens cannot be reused.

---

## 8. Database Migrations

For persistent relational backends (PostgreSQL, SQLite, MySQL), apply `migrations/001_create_email_otps.sql`:

```sql
CREATE TABLE IF NOT EXISTS email_otps (
    id VARCHAR(64) PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    subject VARCHAR(255) NOT NULL,
    purpose VARCHAR(64) NOT NULL,
    otp_hash VARCHAR(128) NOT NULL,
    salt VARCHAR(64) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    max_attempts INT NOT NULL DEFAULT 3,
    attempts INT NOT NULL DEFAULT 0,
    used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_email_otps_email ON email_otps(email);
CREATE INDEX IF NOT EXISTS idx_email_otps_expires ON email_otps(expires_at);
```

---

## 9. Observability & Events

The plugin emits the following events through GoModularAuth's event bus:

- `email_otp.requested`: Emitted when an OTP is dispatched (`OTPRequestedPayload`).
- `email_otp.verified`: Emitted when an OTP is successfully consumed (`OTPVerifiedPayload`).
- `email_otp.rejected`: Emitted on validation or verification failure (`OTPRejectedPayload`).

Plaintext OTP codes are **never** included in event payloads.

---

## 10. License

MIT License. See [LICENSE](LICENSE) for details.
