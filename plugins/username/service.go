package username

import (
	"context"
	"errors"
	"strings"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth/adapter"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
	"github.com/BladiCreator/go-modular-auth/plugins/username/cache"
)

// AuthenticateInput holds credentials for username-based sign in.
type AuthenticateInput struct {
	Username string
	Password string
	Session  auth.SessionOptions
}

// RegisterInput holds user details for registration with a username.
type RegisterInput struct {
	Email    string
	Username string
	Password string
	Session  auth.SessionOptions
}

// Capability defines the typed contract for username operations.
// Applications access it via auth.Get[username.Capability](a) or auth.Get[username.Username](a).
type Capability interface {
	// Authenticate validates the username and password, issuing an opaque session.
	// Applies timing equalization to prevent username enumeration if user does not exist.
	Authenticate(ctx context.Context, in AuthenticateInput) (*auth.AuthResult, error)

	// Register atomically creates a new Core User, Account, Credential, and Username mapping.
	Register(ctx context.Context, in RegisterInput) (*auth.AuthResult, error)

	// Set assigns a username to an existing Core user.
	Set(ctx context.Context, userID, rawUsername string) error

	// Change modifies an existing username for a user, invalidating caches.
	Change(ctx context.Context, userID, newRawUsername string) error

	// Delete removes the username assignment for a user.
	Delete(ctx context.Context, userID string) error

	// GetByUserID retrieves the username record for a given Core user ID.
	GetByUserID(ctx context.Context, userID string) (*Record, error)

	// GetByUsername retrieves the username record for a raw username.
	GetByUsername(ctx context.Context, rawUsername string) (*Record, error)

	// Lookup returns the Core user ID associated with the username.
	Lookup(ctx context.Context, rawUsername string) (string, error)

	// Validate checks if a raw username satisfies validation rules.
	Validate(rawUsername string) error

	// Normalize computes the canonical representation of a raw username.
	Normalize(rawUsername string) (string, error)
}

// Username is a type alias for Capability, supporting both auth.Get[username.Username](a)
// and auth.Get[username.Capability](a).
type Username = Capability

type service struct {
	cfg     Config
	ctx     *sdk.Context
	records *sdk.Repository[Record]
	cache   *cache.Cache
}

func (s *service) Validate(rawUsername string) error {
	return s.cfg.Validator(rawUsername)
}

func (s *service) Normalize(rawUsername string) (string, error) {
	return s.cfg.Normalizer(rawUsername)
}

func recordToCached(r *Record) *cache.CachedRecord {
	if r == nil {
		return nil
	}
	return &cache.CachedRecord{
		UserID:     r.UserID,
		Username:   r.Username,
		Normalized: r.Normalized,
		CreatedAt:  r.CreatedAt,
		UpdatedAt:  r.UpdatedAt,
	}
}

func cachedToRecord(c *cache.CachedRecord) *Record {
	if c == nil {
		return nil
	}
	return &Record{
		UserID:     c.UserID,
		Username:   c.Username,
		Normalized: c.Normalized,
		CreatedAt:  c.CreatedAt,
		UpdatedAt:  c.UpdatedAt,
	}
}

func (s *service) Authenticate(ctx context.Context, in AuthenticateInput) (*auth.AuthResult, error) {
	norm, err := s.Normalize(in.Username)
	if err != nil {
		// Timing equalization: still execute password verification work
		s.dummyTimingVerification(ctx, in.Password, in.Session)
		return nil, ErrInvalidCredentials
	}

	rec, err := s.getNormalized(ctx, norm)
	if errors.Is(err, ErrNotFound) || errors.Is(err, adapter.ErrNotFound) {
		// Timing equalization: username does not exist
		s.dummyTimingVerification(ctx, in.Password, in.Session)
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}

	u, err := s.ctx.Core().GetUser(ctx, rec.UserID)
	if errors.Is(err, auth.ErrUserNotFound) {
		// User was removed from Core: equalize timing
		s.dummyTimingVerification(ctx, in.Password, in.Session)
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}

	// Delegate to Core SignIn: verifies password against Core credential,
	// evaluates email verification rules, issues session, and publishes Core events.
	res, err := s.ctx.Core().SignIn(ctx, auth.SignInInput{
		Email:    u.Email,
		Password: in.Password,
		Session:  in.Session,
	})
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	return res, nil
}

func (s *service) Register(ctx context.Context, in RegisterInput) (*auth.AuthResult, error) {
	if err := s.Validate(in.Username); err != nil {
		return nil, err
	}
	norm, err := s.Normalize(in.Username)
	if err != nil {
		return nil, err
	}

	// Pre-check availability before invoking Core SignUp to fail fast if taken
	if _, err := s.records.FindOne(ctx, adapter.Eq("normalized", norm)); err == nil {
		return nil, ErrTaken
	} else if !errors.Is(err, adapter.ErrNotFound) {
		return nil, err
	}

	var res *auth.AuthResult
	cleanUsername := strings.TrimSpace(in.Username)

	err = s.ctx.Store().Transaction(ctx, func(txCtx context.Context) error {
		// Re-check inside transaction to prevent TOCTOU race
		if _, err := s.records.FindOne(txCtx, adapter.Eq("normalized", norm)); err == nil {
			return ErrTaken
		} else if !errors.Is(err, adapter.ErrNotFound) {
			return err
		}

		var err error
		res, err = s.ctx.Core().SignUp(txCtx, auth.SignUpInput{
			Email:    in.Email,
			Password: in.Password,
			Session:  in.Session,
		})
		if err != nil {
			return err
		}

		now := s.ctx.Now()
		rec := &Record{
			UserID:     res.User.ID,
			Username:   cleanUsername,
			Normalized: norm,
			CreatedAt:  now,
			UpdatedAt:  now,
		}

		if err := s.records.Create(txCtx, rec); err != nil {
			if errors.Is(err, adapter.ErrConflict) {
				return ErrTaken
			}
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	now := s.ctx.Now()
	rec := &Record{
		UserID:     res.User.ID,
		Username:   cleanUsername,
		Normalized: norm,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	s.cache.Set(ctx, recordToCached(rec))

	s.ctx.Events().Publish(ctx, auth.Event{
		Name:    EventCreated,
		Time:    now,
		Subject: res.User.ID,
		Payload: CreatedPayload{
			UserID:     res.User.ID,
			Username:   cleanUsername,
			Normalized: norm,
		},
	})

	return res, nil
}

func (s *service) Set(ctx context.Context, userID, rawUsername string) error {
	if userID == "" {
		return errors.New("username: user ID cannot be empty")
	}
	if err := s.Validate(rawUsername); err != nil {
		return err
	}
	norm, err := s.Normalize(rawUsername)
	if err != nil {
		return err
	}

	// Verify that the user exists in Core
	if _, err := s.ctx.Core().GetUser(ctx, userID); err != nil {
		if errors.Is(err, auth.ErrUserNotFound) {
			return ErrNotFound
		}
		return err
	}

	now := s.ctx.Now()
	cleanUsername := strings.TrimSpace(rawUsername)
	rec := &Record{
		UserID:     userID,
		Username:   cleanUsername,
		Normalized: norm,
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	err = s.ctx.Store().Transaction(ctx, func(txCtx context.Context) error {
		// Ensure user doesn't already have an assigned username
		if _, err := s.records.FindOne(txCtx, adapter.Eq("user_id", userID)); err == nil {
			return ErrAlreadyAssigned
		} else if !errors.Is(err, adapter.ErrNotFound) {
			return err
		}

		if err := s.records.Create(txCtx, rec); err != nil {
			if errors.Is(err, adapter.ErrConflict) {
				return ErrTaken
			}
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}

	s.cache.Set(ctx, recordToCached(rec))
	s.ctx.Events().Publish(ctx, auth.Event{
		Name:    EventCreated,
		Time:    now,
		Subject: userID,
		Payload: CreatedPayload{
			UserID:     userID,
			Username:   rec.Username,
			Normalized: rec.Normalized,
		},
	})
	return nil
}

func (s *service) Change(ctx context.Context, userID, newRawUsername string) error {
	if err := s.Validate(newRawUsername); err != nil {
		return err
	}
	newNorm, err := s.Normalize(newRawUsername)
	if err != nil {
		return err
	}

	var oldRec *Record
	var updatedRec *Record
	now := s.ctx.Now()
	cleanUsername := strings.TrimSpace(newRawUsername)

	err = s.ctx.Store().Transaction(ctx, func(txCtx context.Context) error {
		existing, err := s.records.FindOne(txCtx, adapter.Eq("user_id", userID))
		if errors.Is(err, adapter.ErrNotFound) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		oldRec = existing

		if existing.Normalized != newNorm {
			if _, err := s.records.FindOne(txCtx, adapter.Eq("normalized", newNorm)); err == nil {
				return ErrTaken
			} else if !errors.Is(err, adapter.ErrNotFound) {
				return err
			}
		}

		updatedRec = &Record{
			UserID:     userID,
			Username:   cleanUsername,
			Normalized: newNorm,
			CreatedAt:  existing.CreatedAt,
			UpdatedAt:  now,
		}

		if _, err := s.records.Update(txCtx, []adapter.Condition{adapter.Eq("user_id", userID)}, map[string]any{
			"username":   cleanUsername,
			"normalized": newNorm,
			"updated_at": now,
		}); err != nil {
			if errors.Is(err, adapter.ErrConflict) {
				return ErrTaken
			}
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}

	s.cache.Invalidate(ctx, oldRec.Normalized, userID)
	s.cache.Set(ctx, recordToCached(updatedRec))

	s.ctx.Events().Publish(ctx, auth.Event{
		Name:    EventUpdated,
		Time:    now,
		Subject: userID,
		Payload: UpdatedPayload{
			UserID:        userID,
			OldUsername:   oldRec.Username,
			NewUsername:   updatedRec.Username,
			OldNormalized: oldRec.Normalized,
			NewNormalized: updatedRec.Normalized,
		},
	})
	return nil
}

func (s *service) Delete(ctx context.Context, userID string) error {
	var oldRec *Record
	err := s.ctx.Store().Transaction(ctx, func(txCtx context.Context) error {
		existing, err := s.records.FindOne(txCtx, adapter.Eq("user_id", userID))
		if errors.Is(err, adapter.ErrNotFound) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		oldRec = existing

		_, err = s.records.Delete(txCtx, adapter.Eq("user_id", userID))
		return err
	})
	if err != nil {
		return err
	}

	s.cache.Invalidate(ctx, oldRec.Normalized, userID)
	s.ctx.Events().Publish(ctx, auth.Event{
		Name:    EventDeleted,
		Time:    s.ctx.Now(),
		Subject: userID,
		Payload: DeletedPayload{
			UserID:     userID,
			Username:   oldRec.Username,
			Normalized: oldRec.Normalized,
		},
	})
	return nil
}

func (s *service) GetByUserID(ctx context.Context, userID string) (*Record, error) {
	if rec, ok := s.cache.GetByUserID(ctx, userID); ok {
		return cachedToRecord(rec), nil
	}

	rec, err := s.records.FindOne(ctx, adapter.Eq("user_id", userID))
	if err != nil {
		if errors.Is(err, adapter.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	s.cache.Set(ctx, recordToCached(rec))
	return rec, nil
}

func (s *service) GetByUsername(ctx context.Context, rawUsername string) (*Record, error) {
	norm, err := s.Normalize(rawUsername)
	if err != nil {
		return nil, err
	}
	return s.getNormalized(ctx, norm)
}

func (s *service) Lookup(ctx context.Context, rawUsername string) (string, error) {
	rec, err := s.GetByUsername(ctx, rawUsername)
	if err != nil {
		return "", err
	}
	return rec.UserID, nil
}

func (s *service) getNormalized(ctx context.Context, norm string) (*Record, error) {
	if rec, ok := s.cache.GetByNormalized(ctx, norm); ok {
		return cachedToRecord(rec), nil
	}

	rec, err := s.records.FindOne(ctx, adapter.Eq("normalized", norm))
	if err != nil {
		if errors.Is(err, adapter.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	s.cache.Set(ctx, recordToCached(rec))
	return rec, nil
}

// dummyTimingVerification calls Core's SignIn with an impossible email address to trigger
// password hasher verification against the Core dummy hash, equalizing response timing.
func (s *service) dummyTimingVerification(ctx context.Context, password string, opts auth.SessionOptions) {
	_, _ = s.ctx.Core().SignIn(ctx, auth.SignInInput{
		Email:    "nonexistent-timing-equalizer@gomodularauth.local",
		Password: password,
		Session:  opts,
	})
}
