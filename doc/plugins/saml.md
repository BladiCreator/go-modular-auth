# gomodularauth-saml

`gomodularauth-saml` provides enterprise-grade SAML 2.0 (Security Assertion Markup Language) identity federation for [GoModularAuth](https://github.com/BladiCreator/go-modular-auth).

It acts as a compliant SAML 2.0 Service Provider (SP), abstracting all XML, XMLDSig, and cryptographic complexity away from Core authentication while seamlessly integrating federated identities into Core `User`, `Account` (`saml:<provider_id>`), and `Session` entities.

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
go get github.com/BladiCreator/go-modular-auth-saml
```

---

## 3. Configuration & Registration

Register `saml.New()` as a plugin in GoModularAuth:

```go
package main

import (
    "log"

    "github.com/BladiCreator/go-modular-auth/core"
    saml "github.com/BladiCreator/go-modular-auth-saml"
    samlmem "github.com/BladiCreator/go-modular-auth-saml/store/memory"
)

func main() {
    samlStore := samlmem.New()

    auth, err := core.New(core.Config{
        Plugins: []core.PluginModule{
            saml.New(
                saml.WithStore(samlStore),
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
    samlPlugin, err := core.Get[saml.SAML](auth)
    if err != nil {
        log.Fatalf("failed to resolve SAML capability: %v", err)
    }
}
```

---

## 4. Primary API

The plugin exposes the strongly-typed `saml.SAML` interface via `core.Get[saml.SAML]()`:

```go
type SAML interface {
    // Identity Provider Management
    RegisterIdP(ctx context.Context, in RegisterIdPInput) (*IdPConfig, error)
    RegisterIdPFromMetadata(ctx context.Context, id, orgID string, metadataXML []byte) (*IdPConfig, error)
    GetIdP(ctx context.Context, id string) (*IdPConfig, error)
    ListIdPs(ctx context.Context, orgID string) ([]*IdPConfig, error)
    UpdateIdP(ctx context.Context, in UpdateIdPInput) (*IdPConfig, error)
    DeleteIdP(ctx context.Context, id string) error

    // Service Provider Metadata
    GetSPMetadata(ctx context.Context) ([]byte, error)

    // Authentication Flows
    InitiateAuth(ctx context.Context, in InitiateAuthInput) (*InitiateAuthResult, error)
    ProcessACS(ctx context.Context, in ProcessACSInput) (*AuthResult, error)

    // Account Management
    ListLinkedAccounts(ctx context.Context, userID string) ([]*core.Account, error)
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

## 6. Persistence & Store Contract

The plugin defines an explicit persistence interface `store.Store`:

```go
type Store interface {
    SaveIdP(ctx context.Context, cfg *IdPConfig) error
    GetIdP(ctx context.Context, id string) (*IdPConfig, error)
    GetIdPByEntityID(ctx context.Context, entityID string) (*IdPConfig, error)
    ListIdPs(ctx context.Context, orgID string) ([]*IdPConfig, error)
    DeleteIdP(ctx context.Context, id string) error

    SaveRequest(ctx context.Context, req *RequestSession) error
    GetRequest(ctx context.Context, id string) (*RequestSession, error)
    GetRequestByRelayState(ctx context.Context, relayState string) (*RequestSession, error)
    ConsumeRequest(ctx context.Context, id string, now time.Time) (*RequestSession, error)
    DeleteRequest(ctx context.Context, id string) error
    PurgeExpiredRequests(ctx context.Context, before time.Time) (int, error)

    RecordAssertion(ctx context.Context, assertionID, providerID string, expiresAt, now time.Time) error
    PurgeExpiredAssertions(ctx context.Context, before time.Time) (int, error)
}
```

Included implementations:
- `store/memory`: In-memory thread-safe implementation for tests and local development.
- `migrations/001_create_saml_tables.sql`: Production schema for PostgreSQL.

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
