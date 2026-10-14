package phone_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapter/memory"
	phone "github.com/BladiCreator/go-modular-auth/plugins/phone"
)

func TestSecurity_ConcurrencyAndReplay(t *testing.T) {
	ctx := context.Background()
	provider := phone.NewMockProvider()

	a, err := auth.New(auth.Config{
		Adapter: adaptermem.New(),
		Plugins: []auth.PluginModule{
			phone.New(
				phone.WithProvider(provider),
				phone.WithTTL(5*time.Minute),
				phone.WithAllowSignUp(true),
			),
		},
	})
	if err != nil {
		t.Fatalf("failed to initialize auth: %v", err)
	}

	p, err := auth.Get[phone.Phone](a)
	if err != nil {
		t.Fatalf("failed to retrieve phone capability: %v", err)
	}

	targetPhone := "+12025550199"
	if err := p.RequestOTP(ctx, phone.RequestOTPInput{PhoneNumber: targetPhone}); err != nil {
		t.Fatalf("RequestOTP failed: %v", err)
	}

	code := provider.LastMessage().Code
	const concurrentAttempts = 30

	var (
		successCount  atomic.Int64
		conflictCount atomic.Int64
		otherErrors   atomic.Int64
		wg            sync.WaitGroup
		startBarrier  = make(chan struct{})
	)

	wg.Add(concurrentAttempts)
	for i := 0; i < concurrentAttempts; i++ {
		go func() {
			defer wg.Done()
			<-startBarrier

			_, err := p.VerifyOTP(ctx, phone.VerifyOTPInput{
				PhoneNumber: targetPhone,
				Code:        code,
			})
			if err == nil {
				successCount.Add(1)
			} else if errors.Is(err, phone.ErrCodeAlreadyUsed) {
				conflictCount.Add(1)
			} else {
				otherErrors.Add(1)
			}
		}()
	}

	close(startBarrier)
	wg.Wait()

	if successCount.Load() != 1 {
		t.Fatalf("expected strictly 1 successful consumption, got %d (conflicts: %d, other errors: %d)",
			successCount.Load(), conflictCount.Load(), otherErrors.Load())
	}

	if conflictCount.Load() != concurrentAttempts-1 {
		t.Fatalf("expected %d replays blocked with ErrCodeAlreadyUsed, got %d",
			concurrentAttempts-1, conflictCount.Load())
	}
}

func TestSecurity_BruteForceAndAttemptLimits(t *testing.T) {
	ctx := context.Background()
	provider := phone.NewMockProvider()

	const maxAttempts = 3
	a, err := auth.New(auth.Config{
		Adapter: adaptermem.New(),
		Plugins: []auth.PluginModule{
			phone.New(
				phone.WithProvider(provider),
				phone.WithMaxAttempts(maxAttempts),
				phone.WithAllowSignUp(true),
			),
		},
	})
	if err != nil {
		t.Fatalf("failed to init auth: %v", err)
	}

	p, _ := auth.Get[phone.Phone](a)
	targetPhone := "+12025550288"

	if err := p.RequestOTP(ctx, phone.RequestOTPInput{PhoneNumber: targetPhone}); err != nil {
		t.Fatalf("RequestOTP: %v", err)
	}
	correctCode := provider.LastMessage().Code
	wrongCode := "000000"
	if correctCode == wrongCode {
		wrongCode = "999999"
	}

	for i := 1; i <= maxAttempts; i++ {
		_, err := p.VerifyOTP(ctx, phone.VerifyOTPInput{
			PhoneNumber: targetPhone,
			Code:        wrongCode,
		})
		if err == nil {
			t.Fatalf("attempt %d: expected error on wrong code, got nil", i)
		}
		if i < maxAttempts {
			if !errors.Is(err, phone.ErrInvalidCode) {
				t.Fatalf("attempt %d: expected ErrInvalidCode, got %v", i, err)
			}
		} else {
			if !errors.Is(err, phone.ErrMaxAttemptsExceeded) {
				t.Fatalf("attempt %d: expected ErrMaxAttemptsExceeded on lock, got %v", i, err)
			}
		}
	}

	// Next attempt even with the correct code must be rejected due to lockout
	_, err = p.VerifyOTP(ctx, phone.VerifyOTPInput{
		PhoneNumber: targetPhone,
		Code:        correctCode,
	})
	if !errors.Is(err, phone.ErrMaxAttemptsExceeded) {
		t.Fatalf("attempt with correct code after lockout: expected ErrMaxAttemptsExceeded, got %v", err)
	}
}

func TestSecurity_EnumerationProtection(t *testing.T) {
	ctx := context.Background()
	provider := phone.NewMockProvider()

	// Configure with AllowSignUp = false
	a, err := auth.New(auth.Config{
		Adapter: adaptermem.New(),
		Plugins: []auth.PluginModule{
			phone.New(
				phone.WithProvider(provider),
				phone.WithAllowSignUp(false),
			),
		},
	})
	if err != nil {
		t.Fatalf("failed to init auth: %v", err)
	}

	p, _ := auth.Get[phone.Phone](a)
	unknownPhone := "+12025559999"

	// RequestOTP for unknown phone should return nil without error
	err = p.RequestOTP(ctx, phone.RequestOTPInput{PhoneNumber: unknownPhone})
	if err != nil {
		t.Fatalf("expected nil for enumeration protection, got %v", err)
	}

	// No SMS must be sent
	if len(provider.Messages()) != 0 {
		t.Fatalf("expected 0 messages sent for unregistered phone, got %d", len(provider.Messages()))
	}
}

func TestSecurity_Expiration(t *testing.T) {
	ctx := context.Background()
	provider := phone.NewMockProvider()

	// Short TTL of 50ms
	a, _ := auth.New(auth.Config{
		Adapter: adaptermem.New(),
		Plugins: []auth.PluginModule{
			phone.New(
				phone.WithProvider(provider),
				phone.WithTTL(50*time.Millisecond),
				phone.WithAllowSignUp(true),
			),
		},
	})

	p, _ := auth.Get[phone.Phone](a)
	targetPhone := "+12025550777"

	_ = p.RequestOTP(ctx, phone.RequestOTPInput{PhoneNumber: targetPhone})
	code := provider.LastMessage().Code

	// Sleep past expiration
	time.Sleep(70 * time.Millisecond)

	_, err := p.VerifyOTP(ctx, phone.VerifyOTPInput{
		PhoneNumber: targetPhone,
		Code:        code,
	})
	if !errors.Is(err, phone.ErrCodeExpired) {
		t.Fatalf("expected ErrCodeExpired, got %v", err)
	}
}
