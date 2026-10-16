# GoModularAuth Rate Limit Plugin (`gomodularauth-rate-limit`)

Configurable authentication and security rate limiting for **GoModularAuth** with distributed counter support via the optional Cache Adapter. The Rate Limit plugin prevents brute-force attacks, credential stuffing, enumeration, and denial-of-service against authentication workflows (SignIn, SignUp, PasswordReset, Email OTP, Magic Link, Phone OTP, API Keys, and Administrative actions).

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/rate-limit
```

## Quick Start

```go
package main

import (
	"context"
	"log"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapters/memory"
	ratelimit "github.com/BladiCreator/go-modular-auth/plugins/rate-limit"
	"github.com/BladiCreator/go-modular-auth/plugins/rate-limit/plugins"
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
		Adapter: adaptermem.NewAdapter(),
		Cache:   adaptermem.NewCache(),
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

Detailed guide: [**`doc/plugins/rate-limit.md`**](../../doc/plugins/rate-limit.md).
