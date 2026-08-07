package mock_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain"
	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/internal/mock"
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

	t.Run("Save and retrieve TOTP secret", func(t *testing.T) {
		userID := "usr_123"
		secret := "KVKFKRCPNZQUYWRX"

		err := repo.SaveTOTPSecret(ctx, userID, secret)
		if err != nil {
			t.Fatalf("unexpected error saving TOTP secret: %v", err)
		}

		gotSecret, err := repo.GetTOTPSecret(ctx, userID)
		if err != nil {
			t.Fatalf("expected to retrieve TOTP secret, got error: %v", err)
		}

		if gotSecret != secret {
			t.Errorf("expected secret %s, got %s", secret, gotSecret)
		}
	})

	t.Run("Error retrieving non-existent secret", func(t *testing.T) {
		_, err := repo.GetTOTPSecret(ctx, "usr_unknown")
		if !errors.Is(err, domain.ErrTOTPNotFound) {
			t.Errorf("expected domain.ErrTOTPNotFound, got: %v", err)
		}
	})
}
