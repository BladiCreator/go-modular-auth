# GoModularAuth Plugins

This directory contains standalone, detailed documentation guides for all **35 official plugins** of **GoModularAuth**. Each plugin has its own comprehensive reference covering problem definition, architecture, installation, configuration, capability interfaces, and copy-pasteable usage examples.

---

## Plugin System Architecture

Plugins provide modular capabilities beyond the minimal core authentication engine. They:
1. Implement the `auth.PluginModule` contract (or `sdk.Module`).
2. Interact with the core via the [`plugin-sdk`](file:///media/vladimir/Storage/Projects/Go/go-modular-auth/plugin-sdk) (`sdk.Context`).
3. Expose strongly typed capability interfaces registered via `sdk.Provide[T]` and resolved via `auth.Get[T](engine)` or `auth.MustGet[T](engine)`.
4. Participate in atomic database transactions using `sqltx`.

---

## Directory Index (All 35 Plugins)

### 1. Authentication Factors & Passwordless
- [**Passkeys** (`passkeys.md`)](passkeys.md): FIDO2 / WebAuthn discoverable biometric and security key credentials.
- [**Two-Factor Authentication** (`twofactor.md`)](twofactor.md): Time-based One-Time Passwords (RFC 6238 TOTP), backup recovery codes, and NIST SP 800-63B AAL1/AAL2 assurance levels.
- [**Magic Link** (`magic-link.md`)](magic-link.md): Passwordless login via single-use email links.
- [**Email OTP** (`email-otp.md`)](email-otp.md): Short-lived numeric verification codes delivered via email.
- [**Phone & SMS OTP** (`phone.md`)](phone.md): SMS verification and OTP with E.164 phone normalization.
- [**Account Linking** (`account-linking.md`)](account-linking.md): Secure linking and unlinking of multiple providers to a single user identity.
- [**Username** (`username.md`)](username.md): Username-based registration and authentication.
- [**Anonymous** (`anonymous.md`)](anonymous.md): Guest/temporary sessions with seamless upgrade to permanent accounts.

### 2. Tokens & Session Management
- [**JSON Web Tokens** (`jwt.md`)](jwt.md): Cryptographic JWT issuance (RS256, EdDSA, HS256), JWA signature verification, and revocation tracking.
- [**Bearer** (`bearer.md`)](bearer.md): Standard RFC 6750 Bearer token authentication and validation.
- [**Multi-Session** (`multisession.md`)](multisession.md): Multi-device session tracking, concurrent listing, and remote revocation.
- [**One-Time Token** (`one-time-token.md`)](one-time-token.md): General-purpose secure single-use tokens for custom business ceremonies.

### 3. Single Sign-On (SSO) & Client Protocols
- [**OAuth Client** (`oauth.md`)](oauth.md): Social login integration with Google, GitHub, Discord, Apple, GitLab, etc.
- [**OIDC Client** (`oidc.md`)](oidc.md): OpenID Connect 1.0 client with automated discovery and ID token verification.
- [**SAML Client** (`saml.md`)](saml.md): SAML 2.0 Service Provider (SP) integration for corporate identity providers.
- [**SSO Router** (`sso.md`)](sso.md): Unified SSO orchestrator dynamically routing between SAML and OIDC.

### 4. Identity Provider (IdP) Servers
- [**OAuth 2.1 Provider** (`oauth-provider.md`)](oauth-provider.md): Full OAuth 2.1 Authorization Server (PKCE S256, Client Credentials, Refresh Token Rotation, RFC 7662 Introspection, RFC 7009 Revocation).
- [**OIDC Provider** (`oidc-provider.md`)](oidc-provider.md): OpenID Connect 1.0 Provider issuing ID tokens, discovery metadata, and JWKS.
- [**SAML 2.0 Provider** (`saml-provider.md`)](saml-provider.md): SAML 2.0 Identity Provider (IdP) generating signed XML assertions.
- [**SCIM 2.0 Provider** (`scim.md`)](scim.md): SCIM 2.0 (RFC 7643 / RFC 7644) server for automated user and group provisioning from Okta, Azure AD, etc.

### 5. Multi-Tenancy & Organizations
- [**Organizations** (`organizations.md`)](organizations.md): Multi-tenant organizations, sub-teams, roles (Owner, Admin, Member), and email invitations.

### 6. Authorization & Access Control
- [**RBAC** (`rbac.md`)](rbac.md): Role-Based Access Control, role hierarchies, assignments, and cached evaluations.
- [**Policy (ABAC)** (`policy.md`)](policy.md): Composable Attribute-Based Access Control engine with contextual decision rules.
- [**API Keys** (`api-keys.md`)](api-keys.md): High-performance API key management with salted SHA-256 hashing and scopes.
- [**Admin** (`admin.md`)](admin.md): Privileged user management, account bans, emergency session revocation, and organization-scoped admin (`ForOrg`).

### 7. Autonomous Identities & Modern Clients
- [**AI Agents & MCP** (`agent.md`)](agent.md): First-class identity, short-lived credentials, and scopes for autonomous AI agents and Model Context Protocol (MCP) clients.
- [**Device Authorization** (`device-authorization.md`)](device-authorization.md): OAuth 2.0 Device Authorization Grant (RFC 8628) for CLIs, smart TVs, and headless devices.
- [**Service Accounts** (`service-accounts.md`)](service-accounts.md): Machine-to-machine (M2M) service accounts with granular permissions and secret rotation.

### 8. Governance, Security & Observability
- [**Audit Logging** (`audit.md`)](audit.md): Structured, immutable security audit logging subscribing to core and plugin events.
- [**Rate Limiting** (`rate-limit.md`)](rate-limit.md): Distributed rate limiting using token bucket and sliding window algorithms via `cache.Counter`.
- [**Password Policy** (`password-policy.md`)](password-policy.md): Configurable password strength rules and dictionary attack protections.
- [**Last Login** (`lastlogin.md`)](lastlogin.md): Automatic user login activity, timestamp, and IP tracking.
- [**OpenAPI Generator** (`openapi.md`)](openapi.md): Dynamic OpenAPI 3.0 specification generator reflecting all installed plugins.

### 9. Monetization & Subscriptions
- [**Stripe** (`stripe.md`)](stripe.md): Enterprise subscription billing, customer portal, checkout sessions, and webhook processing.
- [**Polar** (`polar.md`)](polar.md): Polar.sh SaaS billing, subscription verification, digital benefit & license management.
