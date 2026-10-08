package username

import (
	"context"
	"errors"
	"strings"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth-username/cache"
	"github.com/BladiCreator/go-modular-auth-username/store"
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
// Applications access it via auth.Get[username.Capability]() or auth.Get[username.Username]().
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

// Username is a type alias for Capability, supporting both auth.Get[username.Username]()
// and auth.Get[username.Capability]().
type Username = Capability

type service struct {
	cfg   Config
	host  *auth.Host
	store store.Store
	cache *cache.Cache
}

func (s *service) Validate(rawUsername string) error {
	return s.cfg.Validator(rawUsername)
}

func (s *service) Normalize(rawUsername string) (string, error) {
	return s.cfg.Normalizer(rawUsername)
}

func (s *service) Authenticate(ctx context.Context, in AuthenticateInput) (*auth.AuthResult, error) {
	norm, err := s.Normalize(in.Username)
	if err != nil {
		// Timing equalization: still execute password verification work
		s.dummyTimingVerification(ctx, in.Password, in.Session)
		return nil, ErrInvalidCredentials
	}

	rec, err := s.getNormalized(ctx, norm)
	if errors.Is(err, ErrNotFound) || errors.Is(err, store.ErrNotFound) {
		// Timing equalization: username does not exist
		s.dummyTimingVerification(ctx, in.Password, in.Session)
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}

	u, err := s.host.Auth().GetUser(ctx, rec.UserID)
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
	res, err := s.host.Auth().SignIn(ctx, auth.SignInInput{
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
	if _, err := s.store.GetByNormalized(ctx, norm); err == nil {
		return nil, ErrTaken
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}

	var res *auth.AuthResult
	cleanUsername := strings.TrimSpace(in.Username)

	err = s.host.Store().Transaction(ctx, func(txCtx context.Context) error {
		// Re-check inside transaction to prevent TOCTOU race
		if _, err := s.store.GetByNormalized(txCtx, norm); err == nil {
			return ErrTaken
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}

		var err error
		res, err = s.host.Auth().SignUp(txCtx, auth.SignUpInput{
			Email:    in.Email,
			Password: in.Password,
			Session:  in.Session,
		})
		if err != nil {
			return err
		}

		now := s.host.Now()
		rec := &store.Record{
			UserID:     res.User.ID,
			Username:   cleanUsername,
			Normalized: norm,
			CreatedAt:  now,
			UpdatedAt:  now,
		}

		if err := s.store.Create(txCtx, rec); err != nil {
			if errors.Is(err, store.ErrConflict) {
				return ErrTaken
			}
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	now := s.host.Now()
	rec := &store.Record{
		UserID:     res.User.ID,
		Username:   cleanUsername,
		Normalized: norm,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	s.cache.Set(ctx, rec)
	s.host.Events().Publish(ctx, auth.Event{
		Name:    EventCreated,
		Time:    now,
		Subject: res.User.ID,
		Payload: CreatedPayload{
			UserID:     res.User.ID,
			Username:   rec.Username,
			Normalized: rec.Normalized,
		},
	})

	return res, nil
}

func (s *service) Set(ctx context.Context, userID, rawUsername string) error {
	if err := s.Validate(rawUsername); err != nil {
		return err
	}
	norm, err := s.Normalize(rawUsername)
	if err != nil {
		return err
	}

	// Verify user exists in Core
	if _, err := s.host.Auth().GetUser(ctx, userID); err != nil {
		if errors.Is(err, auth.ErrUserNotFound) {
			return ErrUserNotFound
		}
		return err
	}

	now := s.host.Now()
	cleanUsername := strings.TrimSpace(rawUsername)
	rec := &store.Record{
		UserID:     userID,
		Username:   cleanUsername,
		Normalized: norm,
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	err = s.host.Store().Transaction(ctx, func(txCtx context.Context) error {
		// Ensure user doesn't already have an assigned username
		if _, err := s.store.GetByUserID(txCtx, userID); err == nil {
			return ErrAlreadyAssigned
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}

		if err := s.store.Create(txCtx, rec); err != nil {
			if errors.Is(err, store.ErrConflict) {
				return ErrTaken
			}
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}

	s.cache.Set(ctx, rec)
	s.host.Events().Publish(ctx, auth.Event{
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

	var oldRec *store.Record
	var updatedRec *store.Record
	now := s.host.Now()
	cleanUsername := strings.TrimSpace(newRawUsername)

	err = s.host.Store().Transaction(ctx, func(txCtx context.Context) error {
		existing, err := s.store.GetByUserID(txCtx, userID)
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		oldRec = existing

		if existing.Normalized != newNorm {
			if _, err := s.store.GetByNormalized(txCtx, newNorm); err == nil {
				return ErrTaken
			} else if !errors.Is(err, store.ErrNotFound) {
				return err
			}
		}

		updatedRec = &store.Record{
			UserID:     userID,
			Username:   cleanUsername,
			Normalized: newNorm,
			CreatedAt:  existing.CreatedAt,
			UpdatedAt:  now,
		}

		if err := s.store.Update(txCtx, updatedRec); err != nil {
			if errors.Is(err, store.ErrConflict) {
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
	s.cache.Set(ctx, updatedRec)

	s.host.Events().Publish(ctx, auth.Event{
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
	var oldRec *store.Record
	err := s.host.Store().Transaction(ctx, func(txCtx context.Context) error {
		existing, err := s.store.GetByUserID(txCtx, userID)
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		oldRec = existing

		return s.store.Delete(txCtx, userID)
	})
	if err != nil {
		return err
	}

	s.cache.Invalidate(ctx, oldRec.Normalized, userID)
	s.host.Events().Publish(ctx, auth.Event{
		Name:    EventDeleted,
		Time:    s.host.Now(),
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
		return rec, nil
	}

	rec, err := s.store.GetByUserID(ctx, userID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	s.cache.Set(ctx, rec)
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
		return rec, nil
	}

	rec, err := s.store.GetByNormalized(ctx, norm)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	s.cache.Set(ctx, rec)
	return rec, nil
}

// dummyTimingVerification calls Core's SignIn with an impossible email address to trigger
// password hasher verification against the Core dummy hash, equalizing response timing.
func (s *service) dummyTimingVerification(ctx context.Context, password string, opts auth.SessionOptions) {
	_, _ = s.host.Auth().SignIn(ctx, auth.SignInInput{
		Email:    "nonexistent-timing-equalizer@gomodularauth.local",
		Password: password,
		Session:  opts,
	})
}
