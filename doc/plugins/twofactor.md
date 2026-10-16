# GoModularAuth Two-Factor Plugin (`gomodularauth-twofactor`)

[![Go Reference](https://pkg.go.dev/badge/github.com/BladiCreator/go-modular-auth/plugins/twofactor.svg)](https://pkg.go.dev/github.com/BladiCreator/go-modular-auth/plugins/twofactor)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

`gomodularauth-twofactor` provides enterprise-grade, strongly typed Multi-Factor Authentication (MFA) capabilities—including **Time-based One-Time Passwords (TOTP / RFC 6238)** and **single-use Backup Recovery Codes**—for **GoModularAuth**, without coupling the Core authentication model to any specific second factor.

---

## Table of Contents

- [1. Overview & Capabilities](#1-overview--capabilities)
- [2. Installation](#2-installation)
- [3. Configuration & Registration](#3-configuration--registration)
- [4. Primary API (`plugins.TwoFactor`)](#4-primary-api-pluginstwofactor)
- [5. Security Model & Architecture](#5-security-model--architecture)
- [6. Events](#6-events)
- [7. Database Migrations](#7-database-migrations)
- [8. License](#8-license)

---

## 1. Overview & Capabilities

- **TOTP (RFC 6238)**: Support for Google Authenticator, Authy, 1Password, Bitwarden, etc.
- **Backup Recovery Codes**: Single-use cryptographically generated backup codes stored as secure hashes.
- **Secret Protection at Rest**: TOTP secrets are encrypted via AES-256-GCM before persistence and **never exposed** through normal domain queries.
- **Zero-Exposure APIs**: Factored entities returned by domain methods strictly omit secret fields.
- **Replay Protection**: Strict monotonicity checks on time-steps and distributed cache tracking prevent OTP replay attacks.
- **Clock Skew Tolerance**: Configurable time-step window tolerance (default $\pm 1$ step, $\pm 30$ seconds).
- **Authentication Assurance Levels (AAL)**: Formal distinction between single-factor (`aal1`) and multi-factor (`aal2`) states with context propagation helpers (`WithAssuranceLevel`, `RequireAAL2`).
- **MFA Challenges**: Short-lived challenge tokens for step-up authentication or multi-stage login workflows.
- **Observability**: Dispatches `twofactor.enabled`, `twofactor.disabled`, and `twofactor.verified` events without sensitive leaks.
- **Pluggable Persistence & Cache**: Strict Store contract with built-in in-memory store for unit tests and local dev, and transparent cache degradation.

---

## 2. Installation

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/twofactor
```

---

## 3. Configuration & Registration

Register `twofactor.New()` within `auth.New`:

```go
package main

import (
    "log"

    auth "github.com/BladiCreator/go-modular-auth"
    adaptermem "github.com/BladiCreator/go-modular-auth/adapters/memory"
    twofactor "github.com/BladiCreator/go-modular-auth/plugins/twofactor"
    "github.com/BladiCreator/go-modular-auth/plugins/twofactor/plugins"
)

func main() {
    masterKey, _ := twofactor.GenerateRandomKey() // 32 bytes for AES-256-GCM

    authEngine, err := auth.New(auth.Config{
        Adapter: adaptermem.NewAdapter(),
        Plugins: []auth.PluginModule{
            twofactor.New(
                twofactor.WithEncryptionKey(masterKey),
                twofactor.WithIssuer("Acme Corp"),
                twofactor.WithSkewSteps(1),
                twofactor.WithDefaultRecoveryCodesCount(10),
                twofactor.WithEnforceMFAOnSignIn(true),
            ),
        },
    })
    if err != nil {
        log.Fatalf("failed to init auth: %v", err)
    }

    // Strongly typed capability retrieval
    mfa, err := auth.Get[plugins.TwoFactor](authEngine)
    if err != nil {
        log.Fatalf("failed to get twofactor capability: %v", err)
    }
}
```

---

## 4. Primary API (`plugins.TwoFactor`)

```go
type TwoFactor interface {
	// Status & Factors
	GetStatus(ctx context.Context, userID string) (*Status, error)
	IsEnabled(ctx context.Context, userID string) (bool, error)
	ListFactors(ctx context.Context, userID string) ([]Factor, error)

	// TOTP Enrollment & Lifecycle
	EnrollTOTP(ctx context.Context, userID string, opts ...EnrollOption) (*TOTPEnrollment, error)
	ConfirmTOTP(ctx context.Context, userID, factorID, code string) error

	// Verification
	VerifyTOTP(ctx context.Context, userID, code string) (*VerifyResult, error)
	VerifyRecoveryCode(ctx context.Context, userID, code string) (*VerifyResult, error)

	// Two-Step Challenges
	CreateChallenge(ctx context.Context, userID string) (*Challenge, error)
	VerifyChallenge(ctx context.Context, challengeID, code string) (*VerifyResult, error)

	// Backup Recovery Codes
	GenerateRecoveryCodes(ctx context.Context, userID string, count int) ([]string, error)
	RotateRecoveryCodes(ctx context.Context, userID string) ([]string, error)
	GetRemainingRecoveryCodesCount(ctx context.Context, userID string) (int, error)

	// Deactivation
	Disable(ctx context.Context, userID string) error
	DisableFactor(ctx context.Context, userID, factorID string) error
}
```

### 4.1 Enrollment & Confirmation Lifecycle

```go
// 1. Initiate TOTP Enrollment
enrollment, err := mfa.EnrollTOTP(ctx, user.ID,
    twofactor.WithEnrollLabel("Personal iPhone"),
    twofactor.WithEnrollAccountName("alice@example.com"),
)
// enrollment.Secret (base32) and enrollment.ProvisioningURI (otpauth://)
// are returned ONCE for presentation (e.g. QR code).
fmt.Println("Scan URI:", enrollment.ProvisioningURI)

// 2. Confirm Enrollment with initial code
err = mfa.ConfirmTOTP(ctx, user.ID, enrollment.FactorID, "123456")
if err != nil {
    // ErrInvalidCode, ErrReplayDetected, etc.
}
// Factor is now active and twofactor.enabled event is emitted.
```

### 4.2 Recovery Codes Management

```go
// Generate or rotate recovery codes
codes, err := mfa.GenerateRecoveryCodes(ctx, user.ID, 10)
// codes contains plaintext strings like ["4X8K-9LP2-M7NQ", ...]
// Hashes are persisted in the store; plaintext is returned only once.

// Rotate recovery codes (revokes previous unused codes and issues a fresh set)
freshCodes, err := mfa.RotateRecoveryCodes(ctx, user.ID)

// Check remaining count
count, err := mfa.GetRemainingRecoveryCodesCount(ctx, user.ID)
```

### 4.3 Verification

```go
// Verify TOTP code
res, err := mfa.VerifyTOTP(ctx, user.ID, "654321")
if err != nil {
    // ErrInvalidCode, ErrReplayDetected, ErrTwoFactorNotEnabled
}
fmt.Printf("MFA verified! Level: %s\n", res.AssuranceLevel) // "aal2"

// Verify Recovery Code (single-use consumption)
res, err = mfa.VerifyRecoveryCode(ctx, user.ID, "4X8K-9LP2-M7NQ")
```

### 4.4 Multi-Stage Authentication (Challenges)

```go
// After validating primary password (AAL1):
challenge, err := mfa.CreateChallenge(ctx, user.ID)

// Present challenge.ID to client, then verify when client submits second factor:
res, err := mfa.VerifyChallenge(ctx, challenge.ID, userInputCode)
// Works with either TOTP or recovery codes and guarantees single-use consumption.
```

### 4.5 Disablement

```go
// Disable 2FA completely (removes all factors and recovery codes)
err := mfa.Disable(ctx, user.ID)

// Or remove a specific factor
err := mfa.DisableFactor(ctx, user.ID, factorID)
```

---

## 5. Security Model & Architecture

### 5.1 Defense-in-Depth Protections

| Threat | Mitigation Strategy |
| :--- | :--- |
| **Secret Exposure** | TOTP secrets are encrypted via AES-256-GCM. Domain entities (`Factor`) never contain secret fields. |
| **Recovery Code Leakage** | Stored exclusively as SHA-256 hashes. Plaintext strings exist in memory only at generation time. |
| **OTP Replay** | Monotonic `last_used_time_step` tracking on the persistent record and distributed cache markers. |
| **Clock Skew** | Verifies time-steps within $[T - \text{skew}, T + \text{skew}]$ (default $\pm 30$ seconds). |
| **Timing Attacks** | `crypto/subtle.ConstantTimeCompare` used for all recovery code and TOTP comparisons. |
| **Double Consumption** | Atomic condition update `WHERE used_at IS NULL` enforced at the store layer. |

### 5.2 Authentication Assurance Levels (AAL)

`twofactor` adheres to NIST SP 800-63B guidelines:

- `AAL1`: Single-factor authentication (e.g. password only).
- `AAL2`: Multi-factor authentication (primary factor + verified secondary factor).

Use context helpers to gate sensitive endpoints:

```go
// Inside an authorization middleware or service:
if err := twofactor.RequireAAL2(ctx); err != nil {
    return errors.New("insufficient assurance level; please provide MFA")
}
```

---

## 6. Events

| Event Name | Description |
| :--- | :--- |
| `twofactor.enabled` | Emitted when a user confirms their first MFA factor. |
| `twofactor.disabled` | Emitted when 2FA is disabled for a user. |
| `twofactor.verified` | Emitted when a secondary factor (TOTP or recovery code) is verified. |

---

## 7. Database Migrations

SQL migrations are located in `migrations/001_create_twofactor_tables.sql`.

---

## 8. License

MIT
