package emailpassword

import (
	"context"
	"errors"

	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

var (
	ErrUserAlreadyExists = errors.New("emailpassword: user already exists")
	ErrUserNotFound      = errors.New("emailpassword: user not found")
	ErrAccountNotFound   = errors.New("emailpassword: credential account not found")
	ErrInvalidToken      = errors.New("emailpassword: verification token invalid or expired")
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