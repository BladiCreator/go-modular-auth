# GoModularAuth SAML Provider Plugin (`gomodularauth-saml-provider`)

[![Go Reference](https://pkg.go.dev/badge/github.com/BladiCreator/go-modular-auth/plugins/saml-provider.svg)](https://pkg.go.dev/github.com/BladiCreator/go-modular-auth/plugins/saml-provider)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

The **SAML Provider Plugin** (`gomodularauth-saml-provider`, package `samlprovider`) turns your [GoModularAuth](https://github.com/BladiCreator/go-modular-auth) deployment into a SAML 2.0 Identity Provider (IdP). It allows enterprise Service Providers (SPs) such as Salesforce, AWS IAM, Datadog, Zendesk, or custom portals to federate single sign-on authentication through your GoModularAuth user accounts.

---

## Table of Contents

- [Overview & Problem Solved](#overview--problem-solved)
- [Architecture & Design Principles](#architecture--design-principles)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration Options](#configuration-options)
- [Primary Capability API](#primary-capability-api)
- [Persistence & Unified Schema](#persistence--unified-schema)
- [Cache Semantics](#cache-semantics)
- [Observational Events](#observational-events)
- [Security Model & Invariants](#security-model--invariants)
- [Testing & Examples](#testing--examples)
- [License](#license)

---

## Overview & Problem Solved

Enterprises require centralized authentication across dozens of third-party SaaS platforms and internal legacy applications using the SAML 2.0 protocol:

- **Enterprise Single Sign-On (SSO)**: Allows external enterprise apps to delegate user login to your platform.
- **XML Digital Signatures**: Generates standards-compliant SAML 2.0 Assertions signed with RSA-SHA256 (`http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`).
- **Dynamic IdP Metadata**: Automatically produces XML metadata (`EntityDescriptor`) for one-click configuration in external Service Providers.
- **Service Provider Directory**: In-memory registry for trusted SPs, validating Assertion Consumer Service (ACS) URLs and entity IDs.

---

## Architecture & Design Principles

```text
External Enterprise Service Provider (e.g. Salesforce, AWS)
            │
            ├───────────────► 1. Fetch IdP Metadata XML
            │                 GET /saml/metadata
            │
            ├───────────────► 2. SAML AuthnRequest via Browser
            │                 POST /saml/sso
            │
auth.Get[samlprovider.SAMLProvider](engine)
            │
            ▼
┌────────────────────────────────────────────────────────┐
│        gomodularauth-saml-provider (Plugin)            │
│                                                        │
│  - IdP Metadata Generation (EntityDescriptor)          │
│  - Service Provider Directory & ACS Validation         │
│  - SAML 2.0 Response & Assertion XML Builder           │
│  - Canonical XML Enveloped Signature (RSA-SHA256)      │
└──────────────┬──────────────────────────┬──────────────┘
               │                          │
               ▼                          ▼
┌──────────────────────────────┐  ┌──────────────────────┐
│ In-Memory SP Directory       │  │ Core auth.Host       │
│ sps map[string]*SP           │  │  - Context Clock     │
└──────────────────────────────┘  └──────────────────────┘
```

The plugin adheres strictly to GoModularAuth's architectural principles:
- **Zero Heavy XML Dependencies**: Generates standards-compliant XML structures without pulling unmaintained third-party XML libraries.
- **Strict Verification**: Ensures signed responses match the destination ACS URL and SP audience restriction.

---

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/saml-provider
```

---

## Quick Start

```go
package main

import (
	"context"
	"fmt"
	"log"

	auth "github.com/BladiCreator/go-modular-auth"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapters/memory"
	samlprovider "github.com/BladiCreator/go-modular-auth/plugins/saml-provider"
	"github.com/BladiCreator/go-modular-auth/user"
)

func main() {
	ctx := context.Background()

	// 1. Initialize GoModularAuth with SAML Provider plugin
	engine, err := auth.New(auth.Config{
		Adapter: adaptermem.NewAdapter(),
		Plugins: []auth.PluginModule{
			samlprovider.New(
				samlprovider.WithEntityID("https://auth.company.com/saml/idp"),
				samlprovider.WithSSOURL("https://auth.company.com/saml/sso"),
			),
		},
	})
	if err != nil {
		log.Fatalf("failed to initialize auth: %v", err)
	}

	// 2. Resolve SAMLProvider capability
	idp, err := auth.Get[samlprovider.SAMLProvider](engine)
	if err != nil {
		log.Fatalf("failed to resolve SAMLProvider: %v", err)
	}

	// 3. Register a trusted Service Provider (SP)
	err = idp.RegisterSP(&samlprovider.ServiceProvider{
		EntityID: "https://my-app.com/saml/sp",
		ACSURL:   "https://my-app.com/saml/acs",
	})
	if err != nil {
		log.Fatalf("failed to register SP: %v", err)
	}

	// 4. Build signed SAML Response for an authenticated user
	usr := &user.User{
		ID:    "usr_bob",
		Email: "bob@company.com",
	}

	b64Response, err := idp.BuildResponse(ctx, "https://my-app.com/saml/sp", usr, "_request_id_9876")
	if err != nil {
		log.Fatalf("failed to build SAML response: %v", err)
	}

	fmt.Printf("Base64 Encoded SAMLResponse for SP POST: %s\n", b64Response)
}
```

---

## Configuration Options

Configure the plugin using functional options in `samlprovider.New(opts ...Option)`:

```go
samlprovider.New(
    samlprovider.WithEntityID("https://auth.example.com/saml/idp"),
    samlprovider.WithSSOURL("https://auth.example.com/saml/sso"),
    samlprovider.WithSigningKey(privateKey, certBase64DER),
)
```

| Option | Default | Description |
| :--- | :--- | :--- |
| `WithEntityID(entityID string)` | `"https://auth.example.com/saml/idp"` | Sets the canonical Entity ID of this Identity Provider. |
| `WithSSOURL(ssoURL string)` | `"https://auth.example.com/saml/sso"` | Sets the public HTTP-POST / HTTP-Redirect Single Sign-On endpoint URL. |
| `WithSigningKey(pk *rsa.PrivateKey, certBase64 string)` | Generated 2048-bit RSA key and self-signed certificate | Configures the RSA private key and base64 DER X.509 certificate used for XML digital signatures. |

---

## Primary Capability API

The primary capability is exposed through `samlprovider.SAMLProvider`, resolved via `auth.Get[samlprovider.SAMLProvider](engine)`.

### Interface Definition

```go
package samlprovider

import (
	"context"

	"github.com/BladiCreator/go-modular-auth/user"
)

type SAMLProvider interface {
	// GetMetadata generates the SAML 2.0 EntityDescriptor XML metadata for this IdP.
	GetMetadata() ([]byte, error)

	// RegisterSP adds or updates a trusted Service Provider.
	RegisterSP(sp *ServiceProvider) error

	// GetSP retrieves a registered Service Provider by its EntityID.
	GetSP(entityID string) (*ServiceProvider, error)

	// BuildResponse constructs and signs a Base64-encoded SAML 2.0 Response XML for an authenticated user.
	BuildResponse(ctx context.Context, spEntityID string, u *user.User, inResponseTo string) (string, error)
}
```

### Domain Entities

```go
type ServiceProvider struct {
	EntityID    string `json:"entity_id"`
	ACSURL      string `json:"acs_url"`
	Certificate string `json:"certificate,omitempty"`
}
```

### Sentinel Errors

| Error | Description |
| :--- | :--- |
| `ErrSPNotFound` | The requested Service Provider EntityID is not registered. |
| `ErrInvalidSP` | The Service Provider entity has an empty EntityID or ACSURL. |
| `ErrInvalidUser` | Provided `user.User` reference is nil or has an empty ID. |
| `ErrKeyNotConfigured` | Private key or certificate are missing or invalid. |

---

## Persistence & Unified Schema

- **In-Memory Thread-Safe SP Registry**: Registered Service Providers are stored in memory protected by `sync.RWMutex`.
- Applications with dynamic SP provisioning can register SPs dynamically on startup or upon organization configuration.

---

## Cache Semantics

- **IdP Metadata**: The XML output of `GetMetadata()` is static once configured and should be cached via HTTP reverse proxies or CDNs.

---

## Observational Events

- SAML response generation operations can be recorded into Core event audit streams to capture single sign-on activity per Service Provider.

---

## Security Model & Invariants

1. **Digital Signatures**: SAML Responses and Assertions are signed using RSA-SHA256 (`xmldsig-more#rsa-sha256`) with digest algorithm `xmlenc#sha256`.
2. **Replay Protection**: The `inResponseTo` parameter correlates directly to the SP's original `AuthnRequest` ID.
3. **Audience Restriction**: Every generated assertion explicitly sets `<AudienceRestriction>` to the SP's registered Entity ID to ensure tokens cannot be forwarded to unintended relying parties.
4. **Time Boundaries**: Assertions include strict `NotBefore` and `NotOnOrAfter` validity windows (typically 5 minutes) evaluated against `s.ctx.Now()`.

---

## Testing & Examples

Unit test generating signed SAML responses:

```go
func TestSAMLResponseGeneration(t *testing.T) {
	ctx := context.Background()
	engine, _ := auth.New(auth.Config{
		Adapter: adaptermem.NewAdapter(),
		Plugins: []auth.PluginModule{samlprovider.New()},
	})

	idp, _ := auth.Get[samlprovider.SAMLProvider](engine)

	_ = idp.RegisterSP(&samlprovider.ServiceProvider{
		EntityID: "https://sp.test.com",
		ACSURL:   "https://sp.test.com/acs",
	})

	u := &user.User{ID: "usr_saml_test", Email: "test@sp.com"}
	respBase64, err := idp.BuildResponse(ctx, "https://sp.test.com", u, "_req_123")
	if err != nil || respBase64 == "" {
		t.Fatalf("failed to build SAML response: %v", err)
	}
}
```

---

## License

MIT License. See [LICENSE](file:///media/vladimir/Storage/Projects/Go/go-modular-auth/LICENSE) for details.
