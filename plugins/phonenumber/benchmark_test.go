package phonenumber_test

import (
	"context"
	"testing"

	"github.com/BladiCreator/go-modular-auth/plugins/phonenumber"
)

func BenchmarkNumericOTPGenerator(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		_, _ = phonenumber.DefaultNumericOTPGenerator(6)
	}
}

func BenchmarkSHA256Hasher(b *testing.B) {
	hasher := phonenumber.DefaultSHA256Hasher{}
	otp := "123456"
	b.ReportAllocs()

	for b.Loop() {
		hashed, _ := hasher.Hash(otp)
		_ = hasher.Verify(otp, hashed)
	}
}

func BenchmarkAESGCMCipher(b *testing.B) {
	cipher, err := phonenumber.NewAESGCMCipher("my-super-secret-key-for-aes-256")
	if err != nil {
		b.Fatalf("failed to create cipher: %v", err)
	}
	otp := "123456"
	b.ReportAllocs()

	for b.Loop() {
		encrypted, _ := cipher.Encrypt(otp)
		_, _ = cipher.Decrypt(encrypted)
	}
}

func BenchmarkAtomicVerifyOTP(b *testing.B) {
	repo := NewMockRepository()
	p := phonenumber.New(repo,
		phonenumber.WithSendOTP(func(ctx context.Context, data phonenumber.SendOTPData) error {
			return nil
		}),
	)
	ctx := context.Background()
	phone := "+1234567890"

	b.ReportAllocs()

	for b.Loop() {
		b.StopTimer()
		_, _ = p.SendOTP(ctx, phonenumber.SendOTPParams{PhoneNumber: phone})
		otpRes, _ := p.GetVerificationOTP(ctx, phonenumber.GetVerificationOTPParams{
			PhoneNumber: phone,
			Type:        phonenumber.OTPTypeVerification,
		})
		b.StartTimer()

		_, _ = p.Verify(ctx, phonenumber.VerifyParams{
			PhoneNumber: phone,
			Code:        otpRes.OTP,
		})
	}
}
