# GoModularAuth Agent Plugin (`gomodularauth-agent`)

[![Go Reference](https://pkg.go.dev/badge/github.com/BladiCreator/go-modular-auth/plugins/agent.svg)](https://pkg.go.dev/github.com/BladiCreator/go-modular-auth/plugins/agent)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

The **Agent Plugin** provides first-class identity, credential issuance, and capability scoping for autonomous AI agents, LLM tool executors, and Model Context Protocol (MCP) clients.

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/agent
```

## Quick Start

```go
package main

import (
	"context"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapters/memory"
	"github.com/BladiCreator/go-modular-auth/plugins/agent"
)

func main() {
	ctx := context.Background()

	engine, _ := auth.New(auth.Config{
		Adapter: adaptermem.NewAdapter(),
		Plugins: []auth.PluginModule{agent.New()},
	})

	mgr, _ := auth.Get[agent.AgentManager](engine)

	// Create an autonomous agent identity
	ag, _ := mgr.CreateAgent(ctx, "usr_owner_1", "CodeAgent", "Autonomous bot", []string{"repo:read"}, nil)

	// Issue an ephemeral credential (mcp_<hex>)
	token, cred, _ := mgr.IssueCredential(ctx, ag.ID, 30*time.Minute)
	_ = token
	_ = cred

	// Validate credential on tool execution
	authedAgent, _, _ := mgr.ValidateCredential(ctx, token)
	_ = authedAgent
}
```

Detailed guide: [**`doc/plugins/agent.md`**](../../doc/plugins/agent.md).
