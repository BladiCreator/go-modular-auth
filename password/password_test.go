package password_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/BladiCreator/go-modular-auth/password"
)

func TestArgon2idRoundTrip(t *testing.T) {
	ctx := context.Background()
	h := password.NewArgon2id(password.Argon2idParams{Memory: 64, Iterations: 1})
	enc, err := h.Hash(ctx, "s3cret")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(enc, "$argon2id$v=19$m=64,t=1,p=1$") {
		t.Fatalf("unexpected encoding %q", enc)
	}
	if err := h.Verify(ctx, enc, "s3cret"); err != nil {
		t.Fatal(err)
	}
	if err := h.Verify(ctx, enc, "wrong"); !errors.Is(err, password.ErrMismatch) {
		t.Fatalf("want ErrMismatch, got %v", err)
	}
	other, _ := h.Hash(ctx, "s3cret")
	if other == enc {
		t.Fatal("salts must be random")
	}
	// Parameters are read from the hash: a hasher with other params still verifies.
	if err := password.NewArgon2id(password.DefaultArgon2idParams).Verify(ctx, enc, "s3cret"); err != nil {
		t.Fatal(err)
	}
	if err := h.Verify(ctx, "garbage", "s3cret"); !errors.Is(err, password.ErrInvalidHash) {
		t.Fatalf("want ErrInvalidHash, got %v", err)
	}
}
