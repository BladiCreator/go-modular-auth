package password_test

import (
	"context"
	"testing"

	"github.com/BladiCreator/go-modular-auth/password"
)

func BenchmarkArgon2id_FastHash(b *testing.B) {
	hasher := password.NewArgon2id(password.Argon2idParams{
		Memory:      64,
		Iterations:  1,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	})
	ctx := context.Background()
	pwd := "CorrectHorseBatteryStaple123!"

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		h, err := hasher.Hash(ctx, pwd)
		if err != nil {
			b.Fatal(err)
		}
		_ = h
	}
}

func BenchmarkArgon2id_Verify(b *testing.B) {
	hasher := password.NewArgon2id(password.Argon2idParams{
		Memory:      64,
		Iterations:  1,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	})
	ctx := context.Background()
	pwd := "CorrectHorseBatteryStaple123!"
	h, err := hasher.Hash(ctx, pwd)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := hasher.Verify(ctx, h, pwd); err != nil {
			b.Fatal(err)
		}
	}
}
