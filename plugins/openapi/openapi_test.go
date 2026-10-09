package openapi_test

import (
	"encoding/json"
	"testing"

	auth "github.com/BladiCreator/go-modular-auth"
	storememory "github.com/BladiCreator/go-modular-auth/store/memory"
	openapi "github.com/BladiCreator/go-modular-auth-openapi"
)

func TestOpenAPI_SpecGeneration(t *testing.T) {
	mod := openapi.New(
		openapi.WithTitle("Test Service Auth"),
		openapi.WithVersion("2.5.0"),
	)

	a, err := auth.New(auth.Config{
		Store:   storememory.New(),
		Plugins: []auth.PluginModule{mod},
	})
	if err != nil {
		t.Fatalf("failed to create auth engine: %v", err)
	}

	gen, err := auth.Get[openapi.OpenAPIGenerator](a)
	if err != nil {
		t.Fatalf("failed to get OpenAPIGenerator: %v", err)
	}

	doc, err := gen.Generate()
	if err != nil {
		t.Fatalf("failed to generate OpenAPI doc: %v", err)
	}

	if doc.OpenAPI != "3.1.0" {
		t.Errorf("expected openapi 3.1.0, got: %s", doc.OpenAPI)
	}
	if doc.Info.Title != "Test Service Auth" || doc.Info.Version != "2.5.0" {
		t.Errorf("unexpected info: %+v", doc.Info)
	}

	// Verify core endpoints are present
	if _, ok := doc.Paths["/auth/sign-in/email"]; !ok {
		t.Error("expected /auth/sign-in/email endpoint")
	}
	if _, ok := doc.Paths["/auth/session"]; !ok {
		t.Error("expected /auth/session endpoint")
	}

	// Verify JSON output
	rawJSON, err := gen.GenerateJSON(true)
	if err != nil {
		t.Fatalf("failed to generate JSON: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(rawJSON, &parsed); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
}
