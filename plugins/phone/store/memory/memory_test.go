package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth-phone/store"
)

func TestMemoryStore_PhoneCRUD(t *testing.T) {
	ctx := context.Background()
	s := New()

	now := time.Now()
	p := &store.PhoneRecord{
		ID:          "p1",
		UserID:      "u1",
		PhoneNumber: "+12025550123",
		Verified:    false,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	// Create
	if err := s.CreatePhone(ctx, p); err != nil {
		t.Fatalf("CreatePhone failed: %v", err)
	}

	// Conflict on duplicate user ID
	dupUser := &store.PhoneRecord{
		ID:          "p2",
		UserID:      "u1",
		PhoneNumber: "+12025550999",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := s.CreatePhone(ctx, dupUser); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("expected ErrConflict on duplicate UserID, got %v", err)
	}

	// Conflict on duplicate Phone number
	dupPhone := &store.PhoneRecord{
		ID:          "p3",
		UserID:      "u2",
		PhoneNumber: "+12025550123",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := s.CreatePhone(ctx, dupPhone); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("expected ErrConflict on duplicate PhoneNumber, got %v", err)
	}

	// Get by User ID
	got, err := s.GetPhoneByUserID(ctx, "u1")
	if err != nil || got.PhoneNumber != "+12025550123" {
		t.Fatalf("GetPhoneByUserID failed: got=%v, err=%v", got, err)
	}

	// Get by Number
	got, err = s.GetPhoneByNumber(ctx, "+12025550123")
	if err != nil || got.UserID != "u1" {
		t.Fatalf("GetPhoneByNumber failed: got=%v, err=%v", got, err)
	}

	// Update phone record
	got.Verified = true
	got.PhoneNumber = "+12025559876"
	if err := s.UpdatePhone(ctx, got); err != nil {
		t.Fatalf("UpdatePhone failed: %v", err)
	}

	// Check updated values
	updated, err := s.GetPhoneByUserID(ctx, "u1")
	if err != nil || updated.PhoneNumber != "+12025559876" || !updated.Verified {
		t.Fatalf("verification update check failed: %v", updated)
	}

	// Old number should no longer exist
	_, err = s.GetPhoneByNumber(ctx, "+12025550123")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for old number, got %v", err)
	}

	// Delete
	if err := s.DeletePhone(ctx, "u1"); err != nil {
		t.Fatalf("DeletePhone failed: %v", err)
	}

	_, err = s.GetPhoneByUserID(ctx, "u1")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after deletion, got %v", err)
	}
}

func TestMemoryStore_OTPLifecycle(t *testing.T) {
	ctx := context.Background()
	s := New()

	now := time.Now()
	o := &store.OTPRecord{
		ID:          "otp1",
		PhoneNumber: "+12025550123",
		Subject:     "u1",
		Purpose:     "phone:authenticate",
		OTPHash:     "hash123",
		Salt:        "salt123",
		ExpiresAt:   now.Add(5 * time.Minute),
		MaxAttempts: 3,
		Attempts:    0,
		CreatedAt:   now,
	}

	if err := s.CreateOTP(ctx, o); err != nil {
		t.Fatalf("CreateOTP failed: %v", err)
	}

	active, err := s.GetActiveOTP(ctx, "+12025550123", "phone:authenticate", now)
	if err != nil || active.ID != "otp1" {
		t.Fatalf("GetActiveOTP failed: got=%v, err=%v", active, err)
	}

	// Increment attempts
	attempts, err := s.IncrementOTPAttempts(ctx, "otp1")
	if err != nil || attempts != 1 {
		t.Fatalf("IncrementOTPAttempts failed: attempts=%d, err=%v", attempts, err)
	}

	// Mark used
	if err := s.MarkOTPUsed(ctx, "otp1", now); err != nil {
		t.Fatalf("MarkOTPUsed failed: %v", err)
	}

	// Second consumption attempt must fail with conflict
	if err := s.MarkOTPUsed(ctx, "otp1", now); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("expected ErrConflict on re-consumption, got %v", err)
	}

	// Now it is consumed, so GetActiveOTP returns the record with Used() == true
	consumed, err := s.GetActiveOTP(ctx, "+12025550123", "phone:authenticate", now)
	if err != nil || !consumed.Used() {
		t.Fatalf("expected consumed OTP with Used() == true, got %v, err=%v", consumed, err)
	}
}
