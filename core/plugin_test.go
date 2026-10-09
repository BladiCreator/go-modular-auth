package auth_test

import (
	"context"
	"errors"
	"testing"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth/plugin"
	memstore "github.com/BladiCreator/go-modular-auth/store/memory"
	"github.com/BladiCreator/go-modular-auth/user"
)

// Greeter is a capability exposed by the example plugin.
type Greeter interface {
	Greet(ctx context.Context, userID string) (string, error)
}

type greeterModule struct {
	id   string
	deps []string
	init *[]string
}

func (m greeterModule) ID() string             { return m.id }
func (m greeterModule) Dependencies() []string { return m.deps }

func (m greeterModule) Init(h *auth.Host) error {
	*m.init = append(*m.init, m.id)
	if m.id != "greeter" {
		return nil
	}
	h.Hooks().AfterUserCreate(func(context.Context, *user.User) {})
	return auth.Provide[Greeter](h, greeter{h.Auth()})
}

type greeter struct{ a *auth.Auth }

func (g greeter) Greet(ctx context.Context, userID string) (string, error) {
	u, err := g.a.RequireUser(ctx, userID)
	if err != nil {
		return "", err
	}
	return "hello " + u.Email, nil
}

func TestTypedPluginAccess(t *testing.T) {
	ctx := context.Background()
	var order []string
	a, err := auth.New(auth.Config{
		Store:  memstore.New(),
		Hasher: fastHasher,
		Plugins: []auth.PluginModule{
			greeterModule{id: "greeter", deps: []string{"base"}, init: &order},
			greeterModule{id: "base", init: &order},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(order) != 2 || order[0] != "base" {
		t.Fatalf("dependencies must init first: %v", order)
	}
	res, err := a.SignUp(ctx, auth.SignUpInput{Email: "g@x.co", Password: "password1"})
	if err != nil {
		t.Fatal(err)
	}
	g, err := auth.Get[Greeter](a)
	if err != nil {
		t.Fatal(err)
	}
	if msg, _ := g.Greet(ctx, res.User.ID); msg != "hello g@x.co" {
		t.Fatalf("got %q", msg)
	}
	type missing interface{ X() }
	if _, err := auth.Get[missing](a); !errors.Is(err, plugin.ErrNotFound) {
		t.Fatalf("want plugin.ErrNotFound, got %v", err)
	}
}

func TestPluginDependencyValidation(t *testing.T) {
	var order []string
	_, err := auth.New(auth.Config{
		Store:   memstore.New(),
		Plugins: []auth.PluginModule{greeterModule{id: "a", deps: []string{"ghost"}, init: &order}},
	})
	if !errors.Is(err, auth.ErrPluginDependency) {
		t.Fatalf("want ErrPluginDependency, got %v", err)
	}
	_, err = auth.New(auth.Config{
		Store: memstore.New(),
		Plugins: []auth.PluginModule{
			greeterModule{id: "a", deps: []string{"b"}, init: &order},
			greeterModule{id: "b", deps: []string{"a"}, init: &order},
		},
	})
	if !errors.Is(err, auth.ErrPluginDependency) {
		t.Fatalf("cycle must be rejected, got %v", err)
	}
	_, err = auth.New(auth.Config{
		Store: memstore.New(),
		Plugins: []auth.PluginModule{
			greeterModule{id: "a", init: &order},
			greeterModule{id: "a", init: &order},
		},
	})
	if !errors.Is(err, plugin.ErrDuplicate) {
		t.Fatalf("duplicate module must be rejected, got %v", err)
	}
}
