package sdk_test

import (
	"context"
	"errors"
	"testing"

	auth "github.com/BladiCreator/go-modular-auth"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
	memoryStore "github.com/BladiCreator/go-modular-auth/store/memory"
)

type TestCapability interface {
	Greet(name string) string
}

type testCapabilityImpl struct{}

func (testCapabilityImpl) Greet(name string) string {
	return "Hello, " + name
}

type testModule struct {
	initialized bool
	gotStore    bool
	gotEvents   bool
}

func (m *testModule) ID() string {
	return "test-module"
}

func (m *testModule) Init(ctx *sdk.Context) error {
	m.initialized = true
	if ctx.Store() != nil {
		m.gotStore = true
	}
	if ctx.Events() != nil {
		m.gotEvents = true
	}
	ctx.Set("custom-key", 42)
	return sdk.Provide[TestCapability](ctx, testCapabilityImpl{})
}

func TestPluginSDKIntegration(t *testing.T) {
	tm := &testModule{}
	adapted := sdk.Adapt(tm)

	cfg := auth.Config{
		Store:   memoryStore.New(),
		Plugins: []auth.PluginModule{adapted},
	}

	engine, err := auth.New(cfg)
	if err != nil {
		t.Fatalf("auth.New failed: %v", err)
	}

	if !tm.initialized {
		t.Fatal("expected module to be initialized")
	}
	if !tm.gotStore {
		t.Fatal("expected context to provide store")
	}
	if !tm.gotEvents {
		t.Fatal("expected context to provide events")
	}

	cap, err := auth.Get[TestCapability](engine)
	if err != nil {
		t.Fatalf("failed to get capability: %v", err)
	}
	if msg := cap.Greet("World"); msg != "Hello, World" {
		t.Fatalf("unexpected greeting: %s", msg)
	}
}

type depModuleA struct{}

func (depModuleA) ID() string                  { return "dep-a" }
func (depModuleA) Init(ctx *sdk.Context) error { return nil }

type depModuleB struct{}

func (depModuleB) ID() string                  { return "dep-b" }
func (depModuleB) Init(ctx *sdk.Context) error { return nil }
func (depModuleB) Dependencies() []string      { return []string{"dep-a"} }

func TestDependencies(t *testing.T) {
	b := sdk.Adapt(&depModuleB{})
	dep, ok := b.(auth.Dependent)
	if !ok {
		t.Fatal("expected adapted module to implement auth.Dependent")
	}
	deps := dep.Dependencies()
	if len(deps) != 1 || deps[0] != "dep-a" {
		t.Fatalf("unexpected dependencies: %v", deps)
	}

	// Test ResolveInitOrder
	ordered, err := sdk.ResolveInitOrder([]sdk.Module{&depModuleB{}, &depModuleA{}})
	if err != nil {
		t.Fatalf("ResolveInitOrder failed: %v", err)
	}
	if len(ordered) != 2 || ordered[0].ID() != "dep-a" || ordered[1].ID() != "dep-b" {
		t.Fatalf("unexpected init order: %v, %v", ordered[0].ID(), ordered[1].ID())
	}
}

func TestContextBag(t *testing.T) {
	ctx := sdk.NewContext(nil)
	if ctx.ModuleID() != "" {
		t.Fatalf("expected empty module ID, got %s", ctx.ModuleID())
	}
	ctx.Set("user_id", "u_123")
	val, ok := ctx.Get("user_id")
	if !ok || val != "u_123" {
		t.Fatalf("expected value 'u_123', got %v (found: %v)", val, ok)
	}
	_, notFound := ctx.Get("missing")
	if notFound {
		t.Fatal("expected false for missing key")
	}
}

func TestErrors(t *testing.T) {
	baseErr := errors.New("db down")
	err := sdk.NewError(sdk.KindInternal, "operation failed", baseErr)

	if !errors.Is(err, baseErr) {
		t.Fatal("expected unwrapped error to match baseErr")
	}
	if err.Kind != sdk.KindInternal {
		t.Fatalf("expected KindInternal, got %v", err.Kind)
	}
}

func TestHookRegistry(t *testing.T) {
	reg := sdk.NewHookRegistry[string]()
	var executed []string

	reg.Register(func(ctx context.Context, payload string) error {
		executed = append(executed, "hook1:"+payload)
		return nil
	})
	reg.Register(func(ctx context.Context, payload string) error {
		executed = append(executed, "hook2:"+payload)
		return nil
	})

	if err := reg.Execute(context.Background(), "test"); err != nil {
		t.Fatalf("hook execution failed: %v", err)
	}
	if len(executed) != 2 || executed[0] != "hook1:test" || executed[1] != "hook2:test" {
		t.Fatalf("unexpected hook execution: %v", executed)
	}
}
