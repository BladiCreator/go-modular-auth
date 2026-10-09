# GoModularAuth Rate Limit Plugin (`gomodularauth-rate-limit`)

Configurable authentication and security rate limiting for **GoModularAuth** with distributed counter support via the optional Cache Adapter.

The Rate Limit plugin prevents brute-force attacks, credential stuffing, enumeration, and denial-of-service against authentication workflows (SignIn, SignUp, PasswordReset, Email OTP, Magic Link, Phone OTP, API Keys, and Administrative actions).

---

## Features

- **Multiple Algorithms**:
  - **Sliding Window**: Moving window calculation preventing edge-burst vulnerabilities.
  - **Token Bucket**: Allows burst capacity with continuous steady-state token replenishment.
- **Key Dimension Strategies**:
  - **IP-based**: Throttles by client IP address (with IPv6 normalization).
  - **Identity-based**: Throttles by target user ID, email, or username.
  - **Composite**: Combines IP + Identity for fine-grained per-user-per-IP quotas.
- **Zero Secret Exposure**: Passwords, tokens, and raw credentials are never stored in cache keys. Sensitive identities are hashed with SHA-256 before key generation.
- **Distributed Cache & In-Memory Fallback**:
  - Uses `cache.Cache` / `cache.Counter` (e.g. Redis, Valkey) when configured in GoModularAuth.
  - Transparently falls back to thread-safe in-memory counters if no cache adapter is configured.
- **Explicit Fail Mode**: Supports `FailOpen` (prioritizes availability) or `FailClosed` (prioritizes strict defense) when the cache infrastructure experiences errors.
- **Automatic Core Interception**: Integrates natively with Core workflow hooks (`BeforeSignIn`, `BeforeSignUp`, and resets counters on `AfterSignIn`).
- **Typed Capability**: Exposes `auth.Get[plugins.RateLimit]()` for custom programmatic evaluations.

---

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth-rate-limit
```

---

## Architecture

```text
Application / HTTP Router
           ↓
     GoModularAuth Core
           ↓ (Hooks: BeforeSignIn / BeforeSignUp)
gomodularauth-rate-limit (Limiter Engine)
           ↓
    Cache Adapter (cache.Counter) or In-Memory Engine
(Ephemeral counters: gomodularauth:ratelimit:<action>:...)
```

> **Architectural Note**: Rate limiting counters are strictly ephemeral. The persistent database (Store) remains the authoritative source of truth for persistent authentication state and is never contaminated with rate limiting counters.

---

## Registration and Configuration

```go
package main

import (
	"context"
	"log"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	ratelimit "github.com/BladiCreator/go-modular-auth-rate-limit"
	"github.com/BladiCreator/go-modular-auth-rate-limit/plugins"
	corememory "github.com/BladiCreator/go-modular-auth/store/memory"
	corecache "github.com/BladiCreator/go-modular-auth/cache/memory"
)

func main() {
	rlModule := ratelimit.New(
		// Set fail mode behavior when cache adapter fails
		ratelimit.WithDefaultFailMode(ratelimit.FailOpen),

		// Custom policy override for Sign-In
		ratelimit.WithPolicy(ratelimit.Policy{
			Action:    ratelimit.ActionSignIn,
			Algorithm: ratelimit.AlgorithmSlidingWindow,
			Limit:     5,
			Window:    1 * time.Minute,
			KeyType:   ratelimit.KeyTypeComposite, // IP + Identity
		}),

		// Custom policy for API Keys (Token Bucket)
		ratelimit.WithPolicy(ratelimit.Policy{
			Action:     ratelimit.ActionAPIKey,
			Algorithm:  ratelimit.AlgorithmTokenBucket,
			Capacity:   100,
			RefillRate: 50.0, // 50 tokens / second
			KeyType:    ratelimit.KeyTypeIdentity,
		}),
	)

	appAuth, err := auth.New(auth.Config{
		Store:   corememory.New(),
		Cache:   corecache.New(),
		Plugins: []auth.PluginModule{rlModule},
	})
	if err != nil {
		log.Fatal(err)
	}

	// Retrieve typed capability
	limiter, err := auth.Get[plugins.RateLimit](appAuth)
	if err != nil {
		log.Fatal(err)
	}

	// Evaluate manually for custom workflows
	decision, err := limiter.Allow(context.Background(), ratelimit.Request{
		Action:   ratelimit.ActionPasswordReset,
		Identity: "user@example.com",
		IP:       "203.0.113.195",
	})
	if err != nil {
		log.Fatal(err)
	}

	if !decision.Allowed {
		log.Printf("Rate limit exceeded! Retry after %v", decision.RetryAfter)
	}
}
```

---

## Supported Standard Actions

| Action Constant | Target Operation | Default Algorithm | Default Quota | Default Key Type |
| :--- | :--- | :--- | :--- | :--- |
| `ActionSignIn` | User Login | Sliding Window | 5 per 1 min | Composite (IP + ID) |
| `ActionSignUp` | User Registration | Sliding Window | 5 per 10 min | IP |
| `ActionPasswordReset` | Password Reset Request | Sliding Window | 3 per 15 min | Identity |
| `ActionEmailOTP` | Email OTP Request | Sliding Window | 3 per 5 min | Identity |
| `ActionMagicLink` | Magic Link Request | Sliding Window | 3 per 15 min | Identity |
| `ActionPhoneOTP` | Phone SMS OTP | Sliding Window | 3 per 5 min | Identity |
| `ActionAccountRecovery`| Account Recovery | Sliding Window | 2 per 1 hour | Identity |
| `ActionAPIKey` | API Key Requests | Token Bucket | Capacity 100, Refill 50/s | Identity |
| `ActionAdmin` | Administrative Operations| Sliding Window | 30 per 1 min | Identity |

---

## Capability Public API

```go
type RateLimit interface {
    // Check evaluates without consuming capacity.
    Check(ctx context.Context, req Request) (*Decision, error)

    // Allow evaluates and consumes 1 token, returning full decision.
    Allow(ctx context.Context, req Request) (*Decision, error)

    // Require checks and consumes a token, returning ErrRateLimitExceeded if throttled.
    Require(ctx context.Context, req Request) error

    // Reset clears active rate limit counters for a given target.
    Reset(ctx context.Context, req Request) error

    // Policy returns active policy for an action.
    Policy(action string) (Policy, bool)

    // SetPolicy updates policy dynamically at runtime.
    SetPolicy(policy Policy) error
}
```

---

## Security Model

1. **Key Namespacing**: All cache keys use the strict prefix `gomodularauth:ratelimit:<action>:<key_type>:<hash>`.
2. **Secret Privacy**: Identifiers are SHA-256 hashed to prevent sensitive user emails or API key tokens from appearing in telemetry or cache monitors.
3. **IPv6 Collisions**: IPv6 colons are replaced with underscores to prevent delimiter ambiguity in cache backends.
4. **Brute Force Mitigation**: Automatically intercepts Core `BeforeSignIn` and `BeforeSignUp` workflows, terminating suspicious bursts before expensive database and password hashing operations.

---

## Testing

Run tests with race detection:

```bash
go test -count=1 -race -v ./...
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.
