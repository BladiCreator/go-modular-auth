package secure_test

import (
	"testing"

	"github.com/BladiCreator/go-modular-auth/internal/secure"
)

func TestSecurePrimitives(t *testing.T) {
	// 1. NewID entropy and length (16 bytes = 32 hex chars)
	id1 := secure.NewID()
	id2 := secure.NewID()
	if len(id1) != 32 || len(id2) != 32 {
		t.Fatalf("expected 32 hex chars for ID, got len(id1)=%d", len(id1))
	}
	if id1 == id2 {
		t.Fatal("IDs must be unique")
	}

	// 2. NewToken entropy and length (32 bytes raw URL-safe base64 = 43 chars)
	tok1 := secure.NewToken()
	tok2 := secure.NewToken()
	if len(tok1) != 43 || len(tok2) != 43 {
		t.Fatalf("expected 43 base64 chars for 32-byte token, got len=%d", len(tok1))
	}
	if tok1 == tok2 {
		t.Fatal("tokens must be unique")
	}

	// 3. HashToken determinism
	h1 := secure.HashToken(tok1)
	h2 := secure.HashToken(tok1)
	h3 := secure.HashToken(tok2)
	if h1 != h2 {
		t.Fatal("hashes of same token must be identical")
	}
	if h1 == h3 {
		t.Fatal("hashes of distinct tokens must differ")
	}

	// 4. Equal constant time comparison
	if !secure.Equal(tok1, tok1) {
		t.Fatal("identical strings must compare equal")
	}
	if secure.Equal(tok1, tok2) {
		t.Fatal("different strings must not compare equal")
	}
}

func FuzzEqual(f *testing.F) {
	f.Add("secret_token_1", "secret_token_1")
	f.Add("secret_token_1", "secret_token_2")
	f.Add("", "")
	f.Add("a", "b")
	f.Add("short", "much_longer_string_value")

	f.Fuzz(func(t *testing.T, a, b string) {
		eq := secure.Equal(a, b)
		expected := (a == b)
		if eq != expected {
			t.Fatalf("Equal(%q, %q) = %v; want %v", a, b, eq, expected)
		}
	})
}
