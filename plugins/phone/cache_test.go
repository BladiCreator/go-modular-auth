package phone_test

import (
	"context"
	"testing"
	"time"

	phone "github.com/BladiCreator/go-modular-auth/plugins/phone"
)

func TestPhoneCache_SetGetInvalidate(t *testing.T) {
	ctx := context.Background()

	// When underlying cache is nil, operations should be safe no-ops / misses
	pc := phone.NewPhoneCache(nil, 5*time.Minute)
	_, err := pc.GetByUserID(ctx, "u1")
	if err == nil {
		t.Fatal("expected miss on nil cache")
	}

	rec := &phone.PhoneRecord{
		ID:          "p1",
		UserID:      "u1",
		PhoneNumber: "+12025550123",
		Verified:    true,
	}
	if err := pc.SetByUserID(ctx, "u1", rec); err != nil {
		t.Fatalf("unexpected error setting nil cache: %v", err)
	}

	pc.Invalidate(ctx, "u1", "+12025550123")
}
