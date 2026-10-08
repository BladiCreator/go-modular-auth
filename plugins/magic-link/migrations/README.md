# Migrations: gomodularauth-magic-link

## Database Schema Requirements

The `gomodularauth-magic-link` plugin **does not introduce custom database tables**.

It strictly adheres to the GoModularAuth architectural principle:
> *"Never implement its own token primitive when Core already provides the required primitive."*

### Reused Core Persistence

All persistence needs for passwordless magic link authentication are fulfilled by GoModularAuth Core:

1. **Verification Tokens (`verification_tokens`)**:
   - `id`: unique token identifier (`VARCHAR`/`TEXT`).
   - `purpose`: namespaces the token (set to `"magiclink:authenticate"`).
   - `subject`: bound user ID or email (`VARCHAR`/`TEXT`).
   - `token_hash`: SHA-256 hash of the token (`VARCHAR`/`TEXT`, indexed).
   - `expires_at`: token expiration instant (`TIMESTAMP WITH TIME ZONE`).
   - `used_at`: atomic single-use marker (`TIMESTAMP WITH TIME ZONE`, nullable).
   - `created_at`: creation timestamp (`TIMESTAMP WITH TIME ZONE`).

2. **Sessions (`sessions`)**:
   - Server-side opaque sessions created atomically via `auth.CreateSession`.

3. **Users & Accounts (`users`, `accounts`)**:
   - Reused directly for user lookup and account provisioning.

### Store Migration Verification

To run GoModularAuth with this plugin, ensure your Store Adapter (e.g. `go-modular-auth-postgres`, `go-modular-auth-sqlite`) has executed the standard Core migrations. No additional SQL schema changes or migrations are needed.
