package plugin_test

import (
	"encoding/json"
	"testing"

	"github.com/BladiCreator/go-modular-auth/plugin"
)

type SampleParams struct {
	Name string `json:"name"`
	plugin.ExtraContainer
}

func TestExtraContainer(t *testing.T) {
	p := SampleParams{Name: "Test"}

	// Set & Get
	p.Set("key1", "val1")
	val, ok := p.Get("key1")
	if !ok || val != "val1" {
		t.Fatalf("expected val1, got %v, ok=%v", val, ok)
	}

	// Direct Extra field access
	if p.Extra["key1"] != "val1" {
		t.Fatalf("expected direct Extra access val1")
	}

	// JSON Marshal
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	expectedStr := `{"name":"Test","extra":{"key1":"val1"}}`
	if string(data) != expectedStr {
		t.Fatalf("expected JSON %s, got %s", expectedStr, string(data))
	}

	// JSON Unmarshal
	var p2 SampleParams
	if err := json.Unmarshal(data, &p2); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if p2.Name != "Test" {
		t.Fatalf("expected Name Test, got %s", p2.Name)
	}
	val2, ok2 := p2.Get("key1")
	if !ok2 || val2 != "val1" {
		t.Fatalf("expected key1 val1 after unmarshal, got %v, ok=%v", val2, ok2)
	}
}
