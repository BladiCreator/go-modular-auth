package emailpassword

import (
	"context"
	"errors"

	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

var (
	ErrUserAlreadyExists = errors.New("emailpassword: el usuario ya existe")
	ErrUserNotFound      = errors.New("emailpassword: usuario no encontrado")
	ErrAccountNotFound   = errors.New("emailpassword: cuenta credencial no encontrada")
	ErrInvalidToken      = errors.New("emailpassword: token de verificación inválido o expirado")
)

// Repository defines the persistent storage contract required by the EmailPassword plugin.
type Repository interface {
	GetUserByEmail(ctx context.Context, email string) (*entity.User, error)
	GetUserByID(ctx context.Context, id string) (*entity.User, error)
	CreateUser(ctx context.Context, params *dto.CreateUserParams) (*entity.User, error)
	UpdateUser(ctx context.Context, user *entity.User) error
	GetAccountByUserIDAndProvider(ctx context.Context, userID, provider string) (*entity.Account, error)
	CreateAccount(ctx context.Context, account *entity.Account) error
	UpdateAccountPassword(ctx context.Context, accountID, hashedPassword string) error
	CreateVerificationToken(ctx context.Context, token *entity.VerificationToken) error
	GetVerificationToken(ctx context.Context, token string) (*entity.VerificationToken, error)
	DeleteVerificationToken(ctx context.Context, token string) error
}