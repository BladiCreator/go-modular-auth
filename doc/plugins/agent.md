# AI Agent & MCP Client Identity Plugin

The **Agent Plugin** (`plugins/agent`) provides first-class identity, credential issuance, and capability scoping for autonomous AI agents, LLM tool executors, and Model Context Protocol (MCP) clients.

---

## 1. Problem Solved

Autonomous AI agents and MCP tools execute operations on behalf of users or organizations. However, treating AI agents either as human users or as static service accounts introduces severe security flaws:
- **Over-privileged Access**: Agents often receive permanent, long-lived API keys instead of scoped, ephemeral credentials.
- **Lack of Attributability**: Hard to distinguish whether an operation was performed by the human owner or an autonomous tool loop.
- **Tool Expiry**: Agent execution runs require time-bounded credentials that expire automatically after a reasoning loop or task completion.

The `agent` plugin solves this by providing:
- **Dedicated Agent Identities (`Agent`)**: Owned by a human user or tenant (`OwnerID`), with explicit scopes and metadata.
- **Short-Lived Credentials (`Credential`)**: Cryptographically random tokens hashed via SHA-256 (`token_hash`) with automatic expiration (`TTL`).
- **Granular Scopes**: Explicit permission boundaries restricting the tools and APIs the agent is permitted to invoke.
- **Active Lifecycle Management**: Instant agent deactivation and credential revocation.

---

## 2. Installation & Registration

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/agent
```

Register the plugin module:

```go
package main

import (
    auth "github.com/BladiCreator/go-modular-auth"
    "github.com/BladiCreator/go-modular-auth/plugins/agent"
)

func main() {
    agentMod := agent.New()

    engine, err := auth.New(auth.Config{
        Store:   store,
        Plugins: []auth.PluginModule{agentMod},
    })
    if err != nil {
        panic(err)
    }

    // Resolve strongly typed capability
    agentMgr := auth.MustGet[agent.AgentManager](engine)
    _ = agentMgr
}
```

---

## 3. Capability Interface: `agent.AgentManager`

```go
type AgentManager interface {
    CreateAgent(ctx context.Context, ownerID, name, description string, scopes []string, metadata map[string]string) (*Agent, error)
    GetAgent(ctx context.Context, id string) (*Agent, error)
    ListAgents(ctx context.Context, ownerID string) ([]*Agent, error)
    UpdateAgent(ctx context.Context, a *Agent) error
    DeleteAgent(ctx context.Context, id string) error

    IssueCredential(ctx context.Context, agentID string, ttl time.Duration) (string, *Credential, error)
    ValidateCredential(ctx context.Context, token string) (*Agent, *Credential, error)
    RevokeCredential(ctx context.Context, credentialID string) error
}
```

---

## 4. Usage Workflows

### 4.1 Registering an AI Agent Identity
```go
aiAgent, err := agentMgr.CreateAgent(ctx,
    currentUserID,               // Owner ID
    "CodeRefactorAgent",         // Agent Name
    "Autonomous LLM worker refactoring models", // Description
    []string{"repo:read", "code:refactor"},    // Scopes
    map[string]string{"model": "claude-3-5-sonnet", "env": "production"},
)
```

### 4.2 Issuing Short-Lived MCP Credentials
Before delegating a task to an MCP sub-agent or background tool loop, generate an ephemeral credential:

```go
// Issue a credential valid for 30 minutes
rawToken, cred, err := agentMgr.IssueCredential(ctx, aiAgent.ID, 30*time.Minute)
// rawToken is returned to the agent runner once (e.g. Bearer agt_tok_...)
// Only the SHA-256 hash is persisted in the store
```

### 4.3 Authenticating Agent Tool Invocations
When the agent executes an MCP tool or calls your backend API:

```go
agentIdentity, cred, err := agentMgr.ValidateCredential(ctx, rawToken)
if err != nil {
    // ErrInvalidToken or ErrAgentInactive
    return nil, err
}

fmt.Printf("Authenticated Agent: %s (Owner: %s, Scopes: %v)\n",
    agentIdentity.Name, agentIdentity.OwnerID, agentIdentity.Scopes)
```

### 4.4 Revoking Credentials & Deactivating Agents
```go
// Revoke a specific execution credential
err := agentMgr.RevokeCredential(ctx, cred.ID)

// Deactivate the agent completely (instantly rejects all credentials)
aiAgent.Active = false
err = agentMgr.UpdateAgent(ctx, aiAgent)
```
