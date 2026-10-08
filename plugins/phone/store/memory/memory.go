// Package memory implements an in-memory thread-safe store for phone identity and OTP verification.
package memory

import (
	"context"
	"sync"
	"time"

	"github.com/BladiCreator/go-modular-auth-phone/store"
)

// Store implements store.Store using in-memory maps guarded by a read-write mutex.
type Store struct {
	mu             sync.RWMutex
	phonesByID     map[string]*store.PhoneRecord
	phonesByUserID map[string]*store.PhoneRecord
	phonesByNumber map[string]*store.PhoneRecord
	otpsByID       map[string]*store.OTPRecord
}

var _ store.Store = (*Store)(nil)

// New constructs an empty in-memory phone store.
func New() *Store {
	return &Store{
		phonesByID:     make(map[string]*store.PhoneRecord),
		phonesByUserID: make(map[string]*store.PhoneRecord),
		phonesByNumber: make(map[string]*store.PhoneRecord),
		otpsByID:       make(map[string]*store.OTPRecord),
	}
}

// CreatePhone persists a new user phone identity mapping.
func (s *Store) CreatePhone(ctx context.Context, p *store.PhoneRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.phonesByUserID[p.UserID]; exists {
		return store.ErrConflict
	}
	if _, exists := s.phonesByNumber[p.PhoneNumber]; exists {
		return store.ErrConflict
	}
	if _, exists := s.phonesByID[p.ID]; exists {
		return store.ErrConflict
	}

	clone := clonePhone(p)
	s.phonesByID[clone.ID] = clone
	s.phonesByUserID[clone.UserID] = clone
	s.phonesByNumber[clone.PhoneNumber] = clone
	return nil
}

// GetPhoneByUserID retrieves the phone record associated with the Core user ID.
func (s *Store) GetPhoneByUserID(ctx context.Context, userID string) (*store.PhoneRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	rec, ok := s.phonesByUserID[userID]
	if !ok {
		return nil, store.ErrNotFound
	}
	return clonePhone(rec), nil
}

// GetPhoneByNumber retrieves the phone record associated with the canonical phone number.
func (s *Store) GetPhoneByNumber(ctx context.Context, phoneNumber string) (*store.PhoneRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	rec, ok := s.phonesByNumber[phoneNumber]
	if !ok {
		return nil, store.ErrNotFound
	}
	return clonePhone(rec), nil
}

// UpdatePhone updates an existing phone record.
func (s *Store) UpdatePhone(ctx context.Context, p *store.PhoneRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, ok := s.phonesByUserID[p.UserID]
	if !ok {
		return store.ErrNotFound
	}

	// If phone number changed, verify the new number is not taken by another user
	if existing.PhoneNumber != p.PhoneNumber {
		if other, taken := s.phonesByNumber[p.PhoneNumber]; taken && other.UserID != p.UserID {
			return store.ErrConflict
		}
		delete(s.phonesByNumber, existing.PhoneNumber)
	}

	clone := clonePhone(p)
	s.phonesByID[clone.ID] = clone
	s.phonesByUserID[clone.UserID] = clone
	s.phonesByNumber[clone.PhoneNumber] = clone
	return nil
}

// DeletePhone removes the phone record for the given user ID.
func (s *Store) DeletePhone(ctx context.Context, userID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.phonesByUserID[userID]
	if !ok {
		return store.ErrNotFound
	}

	delete(s.phonesByID, rec.ID)
	delete(s.phonesByUserID, rec.UserID)
	delete(s.phonesByNumber, rec.PhoneNumber)
	return nil
}

// CreateOTP persists a new OTP verification record.
func (s *Store) CreateOTP(ctx context.Context, o *store.OTPRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.otpsByID[o.ID]; exists {
		return store.ErrConflict
	}

	s.otpsByID[o.ID] = cloneOTP(o)
	return nil
}

// GetActiveOTP retrieves the latest active OTP record for the phone number and purpose.
func (s *Store) GetActiveOTP(ctx context.Context, phoneNumber, purpose string, now time.Time) (*store.OTPRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	var latest *store.OTPRecord
	for _, rec := range s.otpsByID {
		if rec.PhoneNumber == phoneNumber && rec.Purpose == purpose {
			if latest == nil || rec.CreatedAt.After(latest.CreatedAt) {
				latest = rec
			}
		}
	}

	if latest == nil {
		return nil, store.ErrNotFound
	}

	return cloneOTP(latest), nil
}

// IncrementOTPAttempts atomically increments the failed attempt count.
func (s *Store) IncrementOTPAttempts(ctx context.Context, id string) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.otpsByID[id]
	if !ok {
		return 0, store.ErrNotFound
	}

	rec.Attempts++
	return rec.Attempts, nil
}

// MarkOTPUsed atomically marks an OTP record as consumed if it is unused and unlocked.
func (s *Store) MarkOTPUsed(ctx context.Context, id string, at time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.otpsByID[id]
	if !ok {
		return store.ErrNotFound
	}

	if rec.Used() || rec.Locked() {
		return store.ErrConflict
	}

	usedAt := at
	rec.UsedAt = &usedAt
	return nil
}

// RevokeOTPsByPhone revokes all active OTP records matching the phone and purpose.
func (s *Store) RevokeOTPsByPhone(ctx context.Context, phoneNumber, purpose string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for _, rec := range s.otpsByID {
		if rec.PhoneNumber == phoneNumber && rec.Purpose == purpose && !rec.Used() {
			t := now
			rec.UsedAt = &t
		}
	}
	return nil
}

// DeleteExpiredOTPs removes records expired or consumed prior to the cutoff timestamp.
func (s *Store) DeleteExpiredOTPs(ctx context.Context, before time.Time) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	count := 0
	for id, rec := range s.otpsByID {
		if (rec.Used() && rec.UsedAt.Before(before)) || rec.ExpiresAt.Before(before) {
			delete(s.otpsByID, id)
			count++
		}
	}
	return count, nil
}

func clonePhone(p *store.PhoneRecord) *store.PhoneRecord {
	if p == nil {
		return nil
	}
	c := *p
	if p.VerifiedAt != nil {
		t := *p.VerifiedAt
		c.VerifiedAt = &t
	}
	return &c
}

func cloneOTP(o *store.OTPRecord) *store.OTPRecord {
	if o == nil {
		return nil
	}
	c := *o
	if o.UsedAt != nil {
		t := *o.UsedAt
		c.UsedAt = &t
	}
	return &c
}
