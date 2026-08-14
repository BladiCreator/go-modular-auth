package emailotp_test

import (
	"context"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/plugins/emailotp"
)

func BenchmarkDefaultNumericOTPGenerator(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := emailotp.DefaultNumericOTPGenerator(6)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDefaultSHA256Hasher(b *testing.B) {
	hasher := emailotp.DefaultSHA256Hasher{}
	otp := "123456"
	hash, err := hasher.Hash(otp)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = hasher.Verify(otp, hash)
	}
}

func BenchmarkAESGCMCipher(b *testing.B) {
	cipher, err := emailotp.NewAESGCMCipher("benchmark-secret-key-1234567890")
	if err != nil {
		b.Fatal(err)
	}
	otp := "987654"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		enc, err := cipher.Encrypt(otp)
		if err != nil {
			b.Fatal(err)
		}
		_, err = cipher.Decrypt(enc)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAtomicVerifyOTP(b *testing.B) {
	ctx := context.Background()
	repo := newTestRepo()
	p := emailotp.New(repo, emailotp.WithSendVerificationOTP(func(ctx context.Context, data emailotp.SendEmailData) error {
		return nil
	}))

	user, _ := repo.CreateUser(ctx, &dto.CreateUserParams{
		Email: "bench@example.com",
		Name:  "Benchmark User",
	})

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		identifier := emailotp.ToOTPIdentifier(emailotp.OTPTypeEmailVerification, user.Email)
		_ = repo.CreateVerificationValue(ctx, &emailotp.VerificationRecord{
			ID:         "bench_id",
			Identifier: identifier,
			Value:      "123456:0",
			ExpiresAt:  time.Now().Add(5 * time.Minute),
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		})

		_, _ = p.VerifyEmailOTP(ctx, &emailotp.VerifyEmailOTPParams{
			Email: user.Email,
			OTP:   "123456",
		})
	}
}

func BenchmarkConcurrentAtomicVerifyOTP(b *testing.B) {
	ctx := context.Background()
	repo := newTestRepo()
	p := emailotp.New(repo, emailotp.WithSendVerificationOTP(func(ctx context.Context, data emailotp.SendEmailData) error {
		return nil
	}))

	user, _ := repo.CreateUser(ctx, &dto.CreateUserParams{
		Email: "bench-conc@example.com",
		Name:  "Benchmark Conc User",
	})

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			identifier := emailotp.ToOTPIdentifier(emailotp.OTPTypeEmailVerification, user.Email)
			_ = repo.CreateVerificationValue(ctx, &emailotp.VerificationRecord{
				ID:         "bench_conc_id",
				Identifier: identifier,
				Value:      "654321:0",
				ExpiresAt:  time.Now().Add(5 * time.Minute),
				CreatedAt:  time.Now(),
				UpdatedAt:  time.Now(),
			})

			_, _ = p.VerifyEmailOTP(ctx, &emailotp.VerifyEmailOTPParams{
				Email: user.Email,
				OTP:   "654321",
			})
		}
	})
}
