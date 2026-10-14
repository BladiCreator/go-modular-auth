# GoModularAuth JWT Plugin (`gomodularauth-jwt`)

[![Go Reference](https://pkg.go.dev/badge/github.com/BladiCreator/go-modular-auth-jwt.svg)](https://pkg.go.dev/github.com/BladiCreator/go-modular-auth-jwt)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

An optional, production-grade JWT (JSON Web Token) plugin library for **[GoModularAuth](https://github.com/BladiCreator/go-modular-auth)**.

It provides stateless, cryptographically signed token issuance and verification for integrations requiring decoupled or distributed token verification (e.g. public APIs, microservices, OAuth2/OIDC interoperability, and mobile clients) **without replacing Core server-side opaque Sessions**.

---

## 1. Architectural Principles

- **Sessions Remain Default**: Core GoModularAuth server-side opaque Sessions remain the primary session mechanism. JWT is strictly an opt-in capability for external integrations and never displaces or alters Core Session semantics.
- **Stateless by Default, Revocable when Needed**: Issues pure RFC 7519 signed JWTs. If instant revocation is required, an optional `store.Store` and `cache.RevocationCache` can be attached without altering the stateless contract.
- **Algorithm Confusion Prevention**: Strictly enforces algorithm-key binding. An asymmetric public key can never be evaluated as an HMAC secret, and `alg: "none"` is unconditionally rejected.
- **Zero External Dependencies**: Implemented purely using the Go Standard Library (`crypto/*`, `encoding/json`, `encoding/base64`) and GoModularAuth interfaces.

---

## 2. Installation

```bash
go get github.com/BladiCreator/go-modular-auth-jwt
```

---

## 3. Supported Cryptographic Algorithms

| Algorithm | Key Family | Type | Hash / Curve | Description |
|---|---|---|---|---|
| `HS256`, `HS384`, `HS512` | HMAC | Symmetric | SHA-256, SHA-384, SHA-512 | Shared symmetric secret (min 32 bytes) |
| `RS256`, `RS384`, `RS512` | RSA | Asymmetric | SHA-256, SHA-384, SHA-512 | RSASSA-PKCS1-v1_5 (min 2048-bit) |
| `PS256`, `PS384`, `PS512` | RSA-PSS | Asymmetric | SHA-256, SHA-384, SHA-512 | RSASSA-PSS with PSS salt length = hash |
| `ES256`, `ES384`, `ES512` | ECDSA | Asymmetric | NIST P-256, P-384, P-521 | IEEE P1363 (R \|\| S) signature format |
| `EdDSA` | Ed25519 | Asymmetric | Ed25519 | Pure Ed25519 high-performance signatures |

---

## 4. Quickstart

### 4.1 Register Plugin with GoModularAuth

```go
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"log"
	"time"

	jwt "github.com/BladiCreator/go-modular-auth-jwt"
	"github.com/BladiCreator/go-modular-auth-jwt/plugins"
	"github.com/BladiCreator/go-modular-auth/auth"
	storememory "github.com/BladiCreator/go-modular-auth/store/memory"
)

func main() {
	// Generate an RSA signing key
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	rsaKey, err := jwt.NewRSAKey("prod-key-2026", jwt.RS256, rsaPriv)
	if err != nil {
		log.Fatal(err)
	}

	// Initialize GoModularAuth
	app, err := auth.New(auth.Config{
		Store: storememory.New(), // Core opaque session store
		Plugins: []auth.PluginModule{
			jwt.New(
				jwt.WithKey(rsaKey),
				jwt.WithIssuer("https://auth.mycompany.com"),
				jwt.WithDefaultAudience("https://api.mycompany.com"),
				jwt.WithDefaultTTL(15*time.Minute),
			),
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	// Retrieve the strongly typed JWT capability
	jwtService, err := auth.Get[plugins.JWT](app)
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()

	// 1. Issue Token
	tokenString, err := jwtService.Issue(ctx, jwt.Claims{
		Subject: "usr_991823",
		Custom: map[string]any{
			"role":  "developer",
			"teams": []string{"backend", "platform"},
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Issued JWT: %s\n", tokenString)

	// 2. Verify Token
	claims, err := jwtService.Verify(ctx, tokenString,
		jwt.WithExpectedIssuer("https://auth.mycompany.com"),
		jwt.WithExpectedAudience("https://api.mycompany.com"),
	)
	if err != nil {
		log.Fatalf("Verification failed: %v", err)
	}

	log.Printf("Verified subject: %s, role: %v\n", claims.Subject, claims.Custom["role"])
}
```

---

## 5. Key Rotation

Key rotation allows adding new signing keys without invalidating active tokens signed with previous keys:

```go
km := jwt.NewKeyManager()

// Add initial key
k1, _ := jwt.NewRSAKey("key-v1", jwt.RS256, privKey1)
_ = km.AddKey(k1)

// Later: rotate to key-v2
k2, _ := jwt.NewRSAKey("key-v2", jwt.RS256, privKey2)
_ = km.RotateSigningKey(k2) // Sets key-v2 as the default active signing key

// Existing tokens signed with key-v1 continue to verify because kid is preserved in header.
```

---

## 6. JWKS Export (RFC 7517)

Expose active verification public keys for external API gateways or clients:

```go
jwks, err := jwtService.JWKS(ctx)
if err != nil {
    log.Fatal(err)
}

jwksJSON, _ := jwks.JSON()
// Mount jwksJSON at /.well-known/jwks.json
```

> **Security Note:** Symmetric HMAC keys (`HS256`, `HS384`, `HS512`) are **strictly excluded** from JWKS output to prevent secret disclosure.

---

## 7. Optional Revocation & Blocklist

When individual token invalidation or subject logout is required:

```go
import (
    "github.com/BladiCreator/go-modular-auth-jwt/store/postgres"
    // or store/memory for local development
)

jwtModule := jwt.New(
    jwt.WithKey(rsaKey),
    jwt.WithStore(postgres.New(db)), // Persistent revocation tracking
)

// Revoke a specific token by JTI
err := jwtService.Revoke(ctx, "jti-to-invalidate", expiresAt, "user logged out")

// Revoke all tokens issued to a subject before a timestamp
err := jwtService.RevokeSubject(ctx, "usr_123", time.Now(), "password reset")
```

---

## 8. Configuration Options

| Option | Description |
|---|---|
| `WithKey(key Key)` | Registers a signing or verification key. |
| `WithKeyManager(km KeyManager)` | Supplies a custom key manager. |
| `WithIssuer(iss string)` | Sets default token issuer (`iss`). |
| `WithDefaultAudience(aud ...string)` | Sets default audience (`aud`). |
| `WithDefaultTTL(ttl time.Duration)` | Sets default validity duration (default: 15m). |
| `WithAllowedAlgorithms(algs ...Algorithm)` | Restricts allowed algorithms to a strict whitelist. |
| `WithDefaultLeeway(leeway time.Duration)` | Clock skew tolerance for expiration validation (default: 1m). |
| `WithStore(s store.Store)` | Attaches a persistent revocation store. |
| `WithRevocationCache(c cache.RevocationCache)` | Attaches a revocation cache adapter. |
| `WithHooks(h *Hooks)` | Registers lifecycle interception hooks. |

---

## 9. Security Defenses

1. **Algorithm Confusion**: Each registered key specifies its exact allowed algorithm and key type. An attacker attempting to verify an RSA or EC public key using HMAC (`HS256`) is rejected immediately with `ErrAlgorithmMismatch`.
2. **Strict Non-None Enforcement**: Tokens specifying `alg: "none"` or omitting signatures return `ErrUnsignedTokenNotAllowed`.
3. **Constant-Time Verification**: HMAC verification uses `subtle.ConstantTimeCompare` to prevent timing side-channels.
4. **No Plaintext Secret Exposure**: Events, logs, and JWKS outputs exclude raw keys, secrets, and signatures.
5. **Replay & Skew Defenses**: Strict validation of `exp`, `nbf`, and configurable `leeway`.

---

## 10. License

MIT License. See [LICENSE](LICENSE) for details.
