# GoModularAuth Agent Plugin (`gomodularauth-agent`)

[![Go Reference](https://pkg.go.dev/badge/github.com/BladiCreator/go-modular-auth/plugins/agent.svg)](https://pkg.go.dev/github.com/BladiCreator/go-modular-auth/plugins/agent)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

The **Agent Plugin** (`gomodularauth-agent`) provides first-class identity, credential issuance, and capability scoping for autonomous AI agents, LLM tool executors, and Model Context Protocol (MCP) clients.

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

Autonomous AI agents and MCP tools execute operations on behalf of users or organizations. Treating autonomous agents as human users or assigning them static API keys introduces severe security and architectural flaws:

- **Over-privileged Access**: Agents frequently receive long-lived, high-privilege credentials instead of tightly scoped, ephemeral access.
- **Lack of Attributability**: Hard to distinguish whether an operation was triggered by an interactive human user or an autonomous tool loop.
- **Run-bounded Expiry**: AI execution runs require time-bounded credentials that expire automatically after a reasoning loop or task completion.

The `agent` plugin solves this by providing:

1. **First-Class Agent Entities (`Agent`)**: Bound to an owner (`OwnerID`), with explicit scopes and metadata.
2. **Ephemeral Credentials (`Credential`)**: High-entropy tokens prefixed with `mcp_`, hashed using SHA-256 (`token_hash`) with automatic expiration (`TTL`).
3. **Granular Scopes**: Explicit boundaries restricting the tools and APIs the agent is permitted to invoke.
4. **Active Lifecycle Management**: Instant agent deactivation and credential revocation without database drops.

---

## Architecture & Design Principles

```text
Application / MCP Tool Host
            │
            ▼
auth.Get[agent.AgentManager](engine)
            │
            ▼
┌────────────────────────────────────────────────────────┐
│            gomodularauth-agent (Plugin)                │
│                                                        │
│  - Agent Identity Management                           │
│  - Ephemeral Credential Issuance (mcp_<hex>)          │
│  - Cryptographic Verification (SHA-256 token_hash)    │
│  - Active Lifecycle Invariants                         │
└──────────────┬──────────────────────────┬──────────────┘
               │                          │
               ▼                          ▼
┌──────────────────────────────┐  ┌──────────────────────┐
│ Model: agents                │  │ Core auth.Host       │
│ Model: agent_credentials     │  │  - Engine Lifecycle  │
│ (schema.RegisterSchema)      │  │  - Context Clock     │
└──────────────┬───────────────┘  └──────────────────────┘
               │
               ▼
┌──────────────────────────────┐
│ adapter.Adapter              │
│ (PostgreSQL, SQLite, Memory) │
└──────────────────────────────┘
```

The plugin adheres strictly to GoModularAuth's architectural principles:
- **Zero Core Alteration**: AI Agent entities are registered via the unified schema without modifying Core tables.
- **One-Way Token Hashing**: Plaintext tokens are returned once during generation and never stored; only SHA-256 hex hashes are persisted.
- **Atomic Operations**: All identity and credential operations go through GoModularAuth repository primitives.

---

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/agent
```

---

## Quick Start

```go
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapters/memory"
	"github.com/BladiCreator/go-modular-auth/plugins/agent"
)

func main() {
	ctx := context.Background()

	// 1. Initialize GoModularAuth engine with Agent plugin
	engine, err := auth.New(auth.Config{
		Adapter: adaptermem.NewAdapter(),
		Plugins: []auth.PluginModule{
			agent.New(),
		},
	})
	if err != nil {
		log.Fatalf("failed to initialize auth engine: %v", err)
	}

	// 2. Resolve AgentManager capability
	mgr, err := auth.Get[agent.AgentManager](engine)
	if err != nil {
		log.Fatalf("failed to resolve AgentManager: %v", err)
	}

	// 3. Register an autonomous Agent identity
	ag, err := mgr.CreateAgent(ctx,
		"usr_123456",
		"CodeAuditorAgent",
		"Autonomous code review and security scanner",
		[]string{"repo:read", "audit:write"},
		map[string]string{"runtime": "claude-3-5-sonnet", "environment": "sandbox"},
	)
	if err != nil {
		log.Fatalf("failed to create agent: %v", err)
	}
	fmt.Printf("Created Agent: %s (ID: %s)\n", ag.Name, ag.ID)

	// 4. Issue short-lived credential for a 15-minute tool run
	token, cred, err := mgr.IssueCredential(ctx, ag.ID, 15*time.Minute)
	if err != nil {
		log.Fatalf("failed to issue credential: %v", err)
	}
	fmt.Printf("Ephemeral Token (send to agent once): %s\n", token)
	fmt.Printf("Credential Record ID: %s (Expires: %s)\n", cred.ID, cred.ExpiresAt.Format(time.RFC3339))

	// 5. Authenticate agent request on API invocation
	authenticatedAgent, _, err := mgr.ValidateCredential(ctx, token)
	if err != nil {
		log.Fatalf("credential validation failed: %v", err)
	}
	fmt.Printf("Successfully validated request from agent: %s\n", authenticatedAgent.Name)
}
```

---

## Configuration Options

The plugin constructor `agent.New(opts ...Option)` accepts functional configuration options:

```go
agentMod := agent.New(
    // Extensible options pattern
)
```

| Type / Constructor | Description |
| :--- | :--- |
| `agent.New(opts ...Option) *Module` | Instantiates the Agent module and registers unified schema models. |
| `agent.Config` | Internal configuration structure. |
| `agent.Option` | Functional option closure modifying `*Config`. |

---

## Primary Capability API

The primary capability is exposed through `agent.AgentManager`, resolved via `auth.Get[agent.AgentManager](engine)`.

### Interface Definition

```go
package agent

import (
	"context"
	"time"
)

type AgentManager interface {
	// CreateAgent registers a new agent identity bound to an owner.
	CreateAgent(ctx context.Context, ownerID, name, description string, scopes []string, metadata map[string]string) (*Agent, error)

	// GetAgent retrieves an agent by unique ID. Returns ErrNotFound if missing.
	GetAgent(ctx context.Context, id string) (*Agent, error)

	// ListAgents retrieves all agents registered under a specific owner ID.
	ListAgents(ctx context.Context, ownerID string) ([]*Agent, error)

	// UpdateAgent updates mutable attributes (name, description, scopes, metadata, active status).
	UpdateAgent(ctx context.Context, a *Agent) error

	// DeleteAgent permanently removes an agent record.
	DeleteAgent(ctx context.Context, id string) error

	// IssueCredential generates a secure, ephemeral plaintext token and stores its SHA-256 hash.
	IssueCredential(ctx context.Context, agentID string, ttl time.Duration) (string, *Credential, error)

	// ValidateCredential validates an incoming plaintext token, checking expiration and agent active status.
	ValidateCredential(ctx context.Context, token string) (*Agent, *Credential, error)

	// RevokeCredential deletes a credential record by ID, immediately invalidating the token.
	RevokeCredential(ctx context.Context, credentialID string) error
}
```

### Domain Entities

```go
type Agent struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	OwnerID     string            `json:"owner_id"`
	Scopes      []string          `json:"scopes"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Active      bool              `json:"active"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

type Credential struct {
	ID        string    `json:"id"`
	AgentID   string    `json:"agent_id"`
	TokenHash string    `json:"token_hash"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}
```

### Sentinel Errors

| Error | Description |
| :--- | :--- |
| `ErrNotFound` | The requested agent or credential does not exist. |
| `ErrAgentInactive` | Operation attempted on an agent with `Active == false`. |
| `ErrInvalidToken` | Token is malformed, unrecognized, or expired. |
| `ErrInvalidOwnerID` | Owner ID is empty or invalid during agent creation/query. |
| `ErrInvalidName` | Agent name is empty. |
| `ErrInvalidTTL` | TTL supplied to `IssueCredential` is non-positive. |

---

## Persistence & Unified Schema

The plugin registers two models via `schema.RegisterSchema` with the unified schema provider:

### Model `agents` (`ModelAgents`)
- **Primary Key**: `id` (string, prefixed `agt_<hex>`)
- **Fields**:
  - `id` (TypeString, Required)
  - `name` (TypeString, Required)
  - `description` (TypeString)
  - `owner_id` (TypeString, Required)
  - `scopes` (TypeJSON)
  - `metadata` (TypeJSON)
  - `active` (TypeBool, Required)
  - `created_at` (TypeTime, Required)
  - `updated_at` (TypeTime, Required)
- **Indexes**:
  - `idx_agents_owner_id` on `owner_id`

### Model `agent_credentials` (`ModelAgentCredentials`)
- **Primary Key**: `id` (string, prefixed `cred_<hex>`)
- **Fields**:
  - `id` (TypeString, Required)
  - `agent_id` (TypeString, Required)
  - `token_hash` (TypeString, Required, Unique)
  - `expires_at` (TypeTime, Required)
  - `created_at` (TypeTime, Required)
- **Indexes**:
  - `idx_agent_credentials_token_hash` on `token_hash` (Unique)
  - `idx_agent_credentials_agent_id` on `agent_id`

---

## Cache Semantics

- Lookups by `token_hash` and agent ID rely directly on indexed store queries.
- When pairing with a cache layer, credential validation should cache positive token validations using the remaining TTL of the credential as the cache entry expiration.
- Deactivating an agent or invoking `RevokeCredential` must invalidate associated cache entries.

---

## Observational Events

The agent plugin lifecycle operations can be monitored through Core event dispatcher subscriptions. Typical audit flows log:
- Agent lifecycle transitions (`CreateAgent`, `UpdateAgent`, `DeleteAgent`).
- Ephemeral credential issuance (`IssueCredential`) and revocations (`RevokeCredential`).
- Authentication failures (`ErrAgentInactive`, `ErrInvalidToken`).

---

## Security Model & Invariants

1. **One-Way Cryptographic Storage**: Raw tokens (format `mcp_<32-byte-hex>`) are generated using `crypto/rand` and returned exactly once to the caller. The database stores strictly `sha256.Sum256(token)`.
2. **Automatic Expiry Enforcement**: If `ctx.Now().After(cred.ExpiresAt)`, `ValidateCredential` deletes the expired credential and returns `ErrInvalidToken`.
3. **Active Status Gate**: Even if a token is cryptographically valid and unexpired, authentication fails with `ErrAgentInactive` if `agent.Active == false`.
4. **Owner Scoping**: Agents are bound to an `owner_id`, ensuring multi-tenant isolation across organizations and individual users.

---

## Testing & Examples

Unit tests can run entirely in-memory using `adapters/memory`:

```go
func TestAgentLifecycle(t *testing.T) {
	ctx := context.Background()
	engine, _ := auth.New(auth.Config{
		Adapter: adaptermem.NewAdapter(),
		Plugins: []auth.PluginModule{agent.New()},
	})

	mgr, _ := auth.Get[agent.AgentManager](engine)

	ag, err := mgr.CreateAgent(ctx, "usr_1", "TestBot", "Bot description", []string{"read"}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rawToken, _, err := mgr.IssueCredential(ctx, ag.ID, time.Minute)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	validAg, _, err := mgr.ValidateCredential(ctx, rawToken)
	if err != nil || validAg.ID != ag.ID {
		t.Fatalf("validation failed: %v", err)
	}
}
```

---

## License

MIT License. See [LICENSE](file:///media/vladimir/Storage/Projects/Go/go-modular-auth/LICENSE) for details.
