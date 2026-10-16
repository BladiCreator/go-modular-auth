# GoModularAuth SAML Plugin (`gomodularauth-saml`)

[![Go Reference](https://pkg.go.dev/badge/github.com/BladiCreator/go-modular-auth/plugins/saml.svg)](https://pkg.go.dev/github.com/BladiCreator/go-modular-auth/plugins/saml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

`gomodularauth-saml` provides enterprise-grade SAML 2.0 (Security Assertion Markup Language) identity federation for [GoModularAuth](https://github.com/BladiCreator/go-modular-auth).

It acts as a compliant SAML 2.0 Service Provider (SP), abstracting all XML, XMLDSig, and cryptographic complexity away from Core authentication while seamlessly integrating federated identities into Core `User`, `Account` (`saml:<provider_id>`), and `Session` entities.

---

## Table of Contents

- [1. Features](#1-features)
- [2. Installation](#2-installation)
- [3. Configuration & Registration](#3-configuration--registration)
- [4. Primary API](#4-primary-api)
- [5. Usage Example](#5-usage-example)
- [6. Persistence & Schema](#6-persistence--schema)
- [7. Audit Events](#7-audit-events)
- [8. Security Model](#8-security-model)

---

## 1. Features

- **Protocol Abstraction**: Completely shields Core from XML manipulation, XMLDSig, NameID formats, and SAML bindings.
- **SP Metadata Generation**: Generates compliant SAML 2.0 `<md:EntityDescriptor>` XML with certificates and ACS binding endpoints.
- **IdP Metadata Ingestion**: Parses remote IdP SAML 2.0 metadata XML, extracting SSO endpoints, Entity IDs, and X.509 certificates.
- **SP-Initiated & IdP-Initiated SSO**: Supports standard HTTP-Redirect AuthnRequests (`urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect` with RFC 1951 Deflate + Base64 encoding) and unsolicited IdP-initiated login.
- **Cryptographic Security**:
  - RSA-SHA256 and RSA-SHA1 digital signature verification.
  - Enveloped XMLDSig signature verification over `<SignedInfo>` and payload `<Reference>` `<DigestValue>` checks.
  - X.509 certificate parsing and validation.
- **Validation**:
  - Entity ID and Issuer verification.
  - Audience restriction validation (`<AudienceRestriction>`).
  - Destination URL validation matching configured ACS endpoints.
  - Conditions enforcement (`NotBefore`, `NotOnOrAfter`) with configurable clock skew tolerance.
- **Anti-Replay Protection**:
  - Atomic redemption of AuthnRequest state sessions.
  - Assertion ID replay prevention tracking processed assertion IDs within their validity windows.
- **Identity & Session Integration**:
  - JIT (Just-In-Time) provisioning of Core `User` accounts.
  - Core `Account` linking with provider identifier (`saml:<provider_id>`).
  - Direct issuance of Core authentication tokens and `Session` instances.
- **Multi-Tenancy**: Organization-scoped configuration support for multi-tenant enterprise B2B SaaS.

---

## 2. Installation

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/saml
```

---

## 3. Configuration & Registration

Register `saml.New()` as a plugin in GoModularAuth:

```go
package main

import (
    "log"

    auth "github.com/BladiCreator/go-modular-auth"
    adaptermem "github.com/BladiCreator/go-modular-auth/adapters/memory"
    saml "github.com/BladiCreator/go-modular-auth/plugins/saml"
)

func main() {
    engine, err := auth.New(auth.Config{
        Adapter: adaptermem.NewAdapter(),
        Plugins: []auth.PluginModule{
            saml.New(
                saml.WithSPEntityID("https://myapp.com/saml/metadata"),
                saml.WithSPACSURL("https://myapp.com/saml/acs"),
                saml.WithAutoProvision(true),
            ),
        },
    })
    if err != nil {
        log.Fatalf("failed to initialize auth: %v", err)
    }

    // Resolve typed capability
    samlPlugin, err := auth.Get[saml.SAML](engine)
    if err != nil {
        log.Fatalf("failed to resolve SAML capability: %v", err)
    }
}
```

---

## 4. Primary API

The plugin exposes the strongly-typed `saml.SAML` interface via `auth.Get[saml.SAML]()`:

```go
type SAML interface {
    // Identity Provider Management
    RegisterIdP(ctx context.Context, in RegisterIdPInput) (*IdPConfig, error)
    RegisterIdPFromMetadata(ctx context.Context, id, orgID string, metadataXML []byte) (*IdPConfig, error)
    GetIdP(ctx context.Context, id string) (*IdPConfig, error)
    GetIdPByEntityID(ctx context.Context, entityID string) (*IdPConfig, error)
    ListIdPs(ctx context.Context, orgID string) ([]*IdPConfig, error)
    UpdateIdP(ctx context.Context, in UpdateIdPInput) (*IdPConfig, error)
    DeleteIdP(ctx context.Context, id string) error

    // Service Provider Metadata
    GetSPMetadata(ctx context.Context) ([]byte, error)

    // Authentication Flows
    InitiateAuth(ctx context.Context, in InitiateAuthInput) (*InitiateAuthResult, error)
    ProcessACS(ctx context.Context, in ProcessACSInput) (*AuthResult, error)

    // Account Management
    ListLinkedAccounts(ctx context.Context, userID string) ([]*account.Account, error)
    UnlinkAccount(ctx context.Context, userID, providerID string) error
}
```

---

## 5. Usage Example

### Step 1: Register an Enterprise Identity Provider (Okta / Azure AD)

```go
// Register using XML metadata downloaded from IdP
cfg, err := samlPlugin.RegisterIdPFromMetadata(ctx, "okta-corp", "org_123", oktaMetadataXML)
```

### Step 2: Initiate SP-Initiated Login

```go
initRes, err := samlPlugin.InitiateAuth(ctx, saml.InitiateAuthInput{
    ProviderID:  "okta-corp",
    RedirectURI: "https://myapp.com/dashboard",
})
if err != nil {
    log.Fatal(err)
}

// Redirect the enterprise user to initRes.RedirectURL
// (contains SAMLRequest and RelayState query parameters)
```

### Step 3: Handle ACS HTTP-POST Callback

```go
// In your HTTP ACS endpoint handler:
samlResponse := r.FormValue("SAMLResponse")
relayState := r.FormValue("RelayState")

authResult, err := samlPlugin.ProcessACS(ctx, saml.ProcessACSInput{
    SAMLResponse: samlResponse,
    RelayState:   relayState,
})
if err != nil {
    log.Fatalf("SAML authentication failed: %v", err)
}

// User is authenticated, Core session is active:
fmt.Printf("Authenticated User: %s (ID: %s)\n", authResult.User.Email, authResult.User.ID)
fmt.Printf("Session Token: %s\n", authResult.Token)
fmt.Printf("Redirect target: %s\n", authResult.RedirectURI)
```

---

## 6. Persistence & Schema

SAML provider configurations, request sessions, and processed assertion tracking are persisted via GoModularAuth's unified schema engine (`schema.RegisterSchema`) using the global database adapter:

- Models: `saml_idps` (`IdPConfig`), `saml_requests` (`RequestSession`), and `saml_assertions` (`AssertionRecord`).
- Assertion Deduping: Records processed assertion IDs to prevent replay attacks across distributed cluster nodes.
- Migrations: Located in `migrations/001_create_saml_tables.sql`.

---

## 7. Audit Events

The plugin emits structured security audit events via GoModularAuth Core:

| Event Name | Description |
|---|---|
| `saml.idp.registered` | New SAML Identity Provider registered |
| `saml.idp.updated` | SAML Identity Provider updated |
| `saml.idp.deleted` | SAML Identity Provider removed |
| `saml.authenticated` | Successful SAML login and session issued |
| `saml.failed` | SAML validation or cryptographic error |
| `saml.account.linked` | New Core account federated with SAML NameID |

---

## 8. Security Model

1. **Digital Signature Verification**: IdP assertions must be digitally signed with a registered X.509 certificate.
2. **Replay Protection**:
   - Single-use state sessions prevent reusing AuthnRequest parameters.
   - Processed assertion IDs are recorded within their `NotOnOrAfter` validity window, preventing replay of intercepted assertions.
3. **Audience & Destination Validation**: Ensures responses were generated strictly for this Service Provider and ACS URL.
4. **Clock Skew Tolerance**: Configurable grace period (default 2 minutes) prevents drift issues while strictly enforcing expiry.
5. **No Secret Leakage**: Private keys and unvalidated assertion tokens are never logged or leaked.
