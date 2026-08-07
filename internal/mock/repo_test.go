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

	t.Run("Crear y obtener usuario existente", func(t *testing.T) {
		createdUser, err := repo.CreateUser(ctx, paramsToCreate)
		if err != nil {
			t.Fatalf("no se esperaba error al crear usuario, se obtuvo: %v", err)
		}

		// Buscar por email
		foundByEmail, err := repo.GetUserByEmail(ctx, paramsToCreate.Email)
		if err != nil {
			t.Fatalf("se esperaba encontrar usuario por email, error: %v", err)
		}
		if foundByEmail.ID != createdUser.ID {
			t.Errorf("se esperaba ID %s, se obtuvo %s", createdUser.ID, foundByEmail.ID)
		}

		// Buscar por ID
		foundByID, err := repo.GetUserByID(ctx, createdUser.ID)
		if err != nil {
			t.Fatalf("se esperaba encontrar usuario por ID, error: %v", err)
		}
		if foundByID.Email != paramsToCreate.Email {
			t.Errorf("se esperaba email %s, se obtuvo %s", paramsToCreate.Email, foundByID.Email)
		}
	})

	t.Run("Manejo de errores cuando el usuario no existe", func(t *testing.T) {
		_, err := repo.GetUserByEmail(ctx, "desconocido@example.com")
		if !errors.Is(err, domain.ErrUserNotFound) {
			t.Errorf("se esperaba domain.ErrUserNotFound por email, se obtuvo: %v", err)
		}

		_, err = repo.GetUserByID(ctx, "usr_unknown")
		if !errors.Is(err, domain.ErrUserNotFound) {
			t.Errorf("se esperaba domain.ErrUserNotFound por ID, se obtuvo: %v", err)
		}
	})
}

func TestMockRepo_SessionOperations(t *testing.T) {
	ctx := context.Background()
	repo := mock.NewMockRepo()

	sessionParams := &dto.CreateSessionParams{
		UserID:    "usr_123",
		Token:     "token_secreto_abc",
		IPAddress: "127.0.0.1",
		UserAgent: "TestAgent",
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
	}

	t.Run("Crear, consultar y eliminar sesión", func(t *testing.T) {
		// 1. Crear sesión
		createdSession, err := repo.CreateSession(ctx, sessionParams)
		if err != nil {
			t.Fatalf("error al crear la sesión: %v", err)
		}

		// 2. Obtener por token
		found, err := repo.GetSessionByToken(ctx, createdSession.Token)
		if err != nil {
			t.Fatalf("error al obtener la sesión por token: %v", err)
		}
		if found.UserID != createdSession.UserID {
			t.Errorf("se esperaba UserID %s, se obtuvo %s", createdSession.UserID, found.UserID)
		}

		// 3. Eliminar sesión
		err = repo.DeleteSession(ctx, createdSession.Token)
		if err != nil {
			t.Fatalf("error al eliminar la sesión: %v", err)
		}

		// 4. Verificar que ya no existe
		_, err = repo.GetSessionByToken(ctx, createdSession.Token)
		if !errors.Is(err, domain.ErrSessionNotFound) {
			t.Errorf("se esperaba domain.ErrSessionNotFound tras eliminar, se obtuvo: %v", err)
		}
	})
}

func TestMockRepo_2FAOperations(t *testing.T) {
	ctx := context.Background()
	repo := mock.NewMockRepo()

	t.Run("Guardar y obtener secreto TOTP", func(t *testing.T) {
		userID := "usr_123"
		secret := "KVKFKRCPNZQUYWRX"

		err := repo.SaveTOTPSecret(ctx, userID, secret)
		if err != nil {
			t.Fatalf("no se esperaba error al guardar secreto TOTP, se obtuvo: %v", err)
		}

		gotSecret, err := repo.GetTOTPSecret(ctx, userID)
		if err != nil {
			t.Fatalf("se esperaba encontrar secreto TOTP, error: %v", err)
		}

		if gotSecret != secret {
			t.Errorf("se esperaba secreto %s, se obtuvo %s", secret, gotSecret)
		}
	})

	t.Run("Error al obtener secreto inexistente", func(t *testing.T) {
		_, err := repo.GetTOTPSecret(ctx, "usr_desconocido")
		if !errors.Is(err, domain.ErrTOTPNotFound) {
			t.Errorf("se esperaba domain.ErrTOTPNotFound, se obtuvo: %v", err)
		}
	})
}
