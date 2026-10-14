package agent_test

import (
	"context"
	"testing"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapter/memory"
	agent "github.com/BladiCreator/go-modular-auth/plugins/agent"
)

func TestAgent_Lifecycle(t *testing.T) {
	ctx := context.Background()
	mod := agent.New()

	a, err := auth.New(auth.Config{
		Adapter: adaptermem.New(),
		Plugins: []auth.PluginModule{mod},
	})
	if err != nil {
		t.Fatalf("failed to create auth engine: %v", err)
	}

	mgr, err := auth.Get[agent.AgentManager](a)
	if err != nil {
		t.Fatalf("failed to get AgentManager capability: %v", err)
	}

	// 1. Create agent
	ag, err := mgr.CreateAgent(ctx, "owner-1", "Coding Bot", "Autonomous dev agent", []string{"repo:read", "repo:write"}, map[string]string{"env": "prod"})
	if err != nil {
		t.Fatalf("failed to create agent: %v", err)
	}
	if ag.ID == "" || ag.Name != "Coding Bot" {
		t.Fatalf("unexpected agent: %+v", ag)
	}

	// 2. Issue credential
	token, cred, err := mgr.IssueCredential(ctx, ag.ID, 1*time.Hour)
	if err != nil {
		t.Fatalf("failed to issue credential: %v", err)
	}
	if token == "" || cred == nil {
		t.Fatal("expected non-empty token and credential")
	}

	// 3. Validate valid credential
	vAgent, vCred, err := mgr.ValidateCredential(ctx, token)
	if err != nil {
		t.Fatalf("expected successful validation: %v", err)
	}
	if vAgent.ID != ag.ID || vCred.ID != cred.ID {
		t.Errorf("validation returned mismatched agent or credential")
	}

	// 4. Validate invalid credential
	_, _, err = mgr.ValidateCredential(ctx, "invalid-token")
	if err != agent.ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken, got: %v", err)
	}

	// 5. Revoke credential
	if err := mgr.RevokeCredential(ctx, cred.ID); err != nil {
		t.Fatalf("failed to revoke credential: %v", err)
	}
	_, _, err = mgr.ValidateCredential(ctx, token)
	if err != agent.ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken after revocation, got: %v", err)
	}
}
