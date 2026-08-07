package mock_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain"
	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/internal/mock"
	"github.com/BladiCreator/go-modular-auth/plugins/twofactor"
)

func TestMockRepo_UserOperations(t *testing.T) {
	ctx := context.Background()
	repo := mock.NewMockRepo()

	paramsToCreate := &dto.CreateUserParams{
		Name:  "Dev User",
		Email: "dev@example.com",
	}

	t.Run("Create and retrieve existing user", func(t *testing.T) {
		createdUser, err := repo.CreateUser(ctx, paramsToCreate)
		if err != nil {
			t.Fatalf("unexpected error creating user: %v", err)
		}

		// Find by email
		foundByEmail, err := repo.GetUserByEmail(ctx, paramsToCreate.Email)
		if err != nil {
			t.Fatalf("expected to find user by email, got error: %v", err)
		}
		if foundByEmail.ID != createdUser.ID {
			t.Errorf("expected ID %s, got %s", createdUser.ID, foundByEmail.ID)
		}

		// Find by ID
		foundByID, err := repo.GetUserByID(ctx, createdUser.ID)
		if err != nil {
			t.Fatalf("expected to find user by ID, got error: %v", err)
		}
		if foundByID.Email != paramsToCreate.Email {
			t.Errorf("expected email %s, got %s", paramsToCreate.Email, foundByID.Email)
		}
	})

	t.Run("Error handling when user does not exist", func(t *testing.T) {
		_, err := repo.GetUserByEmail(ctx, "unknown@example.com")
		if !errors.Is(err, domain.ErrUserNotFound) {
			t.Errorf("expected domain.ErrUserNotFound by email, got: %v", err)
		}

		_, err = repo.GetUserByID(ctx, "usr_unknown")
		if !errors.Is(err, domain.ErrUserNotFound) {
			t.Errorf("expected domain.ErrUserNotFound by ID, got: %v", err)
		}
	})
}

func TestMockRepo_SessionOperations(t *testing.T) {
	ctx := context.Background()
	repo := mock.NewMockRepo()

	sessionParams := &dto.CreateSessionParams{
		UserID:    "usr_123",
		Token:     "secret_token_abc",
		IPAddress: "127.0.0.1",
		UserAgent: "TestAgent",
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
	}

	t.Run("Create, query, and delete session", func(t *testing.T) {
		// 1. Create session
		createdSession, err := repo.CreateSession(ctx, sessionParams)
		if err != nil {
			t.Fatalf("error creating session: %v", err)
		}

		// 2. Retrieve by token
		found, err := repo.GetSessionByToken(ctx, createdSession.Token)
		if err != nil {
			t.Fatalf("error retrieving session by token: %v", err)
		}
		if found.UserID != createdSession.UserID {
			t.Errorf("expected UserID %s, got %s", createdSession.UserID, found.UserID)
		}

		// 3. Delete session
		err = repo.DeleteSession(ctx, createdSession.Token)
		if err != nil {
			t.Fatalf("error deleting session: %v", err)
		}

		// 4. Verify session no longer exists
		_, err = repo.GetSessionByToken(ctx, createdSession.Token)
		if !errors.Is(err, domain.ErrSessionNotFound) {
			t.Errorf("expected domain.ErrSessionNotFound after deletion, got: %v", err)
		}
	})
}

func TestMockRepo_2FAOperations(t *testing.T) {
	ctx := context.Background()
	repo := mock.NewMockRepo()

	t.Run("Create, find, update and delete TwoFactor entity", func(t *testing.T) {
		userID := "usr_123"
		tf := &twofactor.TwoFactor{
			UserID:      userID,
			Secret:      "KVKFKRCPNZQUYWRX",
			BackupCodes: `["CODE1", "CODE2"]`,
			Verified:    true,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}

		err := repo.Create(ctx, tf)
		if err != nil {
			t.Fatalf("unexpected error creating TwoFactor: %v", err)
		}

		gotTF, err := repo.FindByUserID(ctx, userID)
		if err != nil {
			t.Fatalf("expected to find TwoFactor by userID, got error: %v", err)
		}
		if gotTF.Secret != tf.Secret {
			t.Errorf("expected secret %s, got %s", tf.Secret, gotTF.Secret)
		}

		tf.Failures = 2
		err = repo.Update(ctx, tf)
		if err != nil {
			t.Fatalf("unexpected error updating TwoFactor: %v", err)
		}

		updatedTF, _ := repo.FindByUserID(ctx, userID)
		if updatedTF.Failures != 2 {
			t.Errorf("expected 2 failures, got %d", updatedTF.Failures)
		}

		err = repo.DeleteByUserID(ctx, userID)
		if err != nil {
			t.Fatalf("unexpected error deleting TwoFactor: %v", err)
		}

		_, err = repo.FindByUserID(ctx, userID)
		if !errors.Is(err, twofactor.ErrTwoFactorNotEnabled) {
			t.Errorf("expected twofactor.ErrTwoFactorNotEnabled after delete, got: %v", err)
		}
	})

	t.Run("Save, get and delete OTPChallenge", func(t *testing.T) {
		key := "2fa-otp-usr_123"
		challenge := &twofactor.OTPChallenge{
			Key:       key,
			UserID:    "usr_123",
			CodeHash:  "123456",
			Attempts:  0,
			ExpiresAt: time.Now().Add(3 * time.Minute),
		}

		err := repo.SaveOTPChallenge(ctx, challenge)
		if err != nil {
			t.Fatalf("unexpected error saving OTP challenge: %v", err)
		}

		gotChallenge, err := repo.GetOTPChallenge(ctx, key)
		if err != nil {
			t.Fatalf("expected to find OTP challenge, got error: %v", err)
		}
		if gotChallenge.CodeHash != "123456" {
			t.Errorf("expected code hash 123456, got %s", gotChallenge.CodeHash)
		}

		err = repo.DeleteOTPChallenge(ctx, key)
		if err != nil {
			t.Fatalf("unexpected error deleting OTP challenge: %v", err)
		}

		_, err = repo.GetOTPChallenge(ctx, key)
		if !errors.Is(err, twofactor.ErrOTPExpired) {
			t.Errorf("expected twofactor.ErrOTPExpired after delete, got: %v", err)
		}
	})
}
