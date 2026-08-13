package emailpassword

import (
	"context"
	"errors"

	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

var (
	// ErrUserAlreadyExists is returned when attempting to register an email address already bound to an existing user.
	ErrUserAlreadyExists = errors.New("emailpassword: user already exists")

	// ErrUserNotFound is returned by repository methods when no user record matches the queried identifier or email.
	ErrUserNotFound = errors.New("emailpassword: user not found")

	// ErrAccountNotFound is returned when credentials for the requested provider are missing in storage.
	ErrAccountNotFound = errors.New("emailpassword: credential account not found")

	// ErrInvalidToken is returned when a password reset or email verification token does not exist in storage.
	ErrInvalidToken = errors.New("emailpassword: verification token invalid")

	// ErrTokenExpired is returned when a submitted verification or reset token has passed its expiration time.
	ErrTokenExpired = errors.New("emailpassword: token has expired")

	// ErrInvalidCurrentPass is returned when the user provides an incorrect current password during a password change.
	ErrInvalidCurrentPass = errors.New("emailpassword: current password is incorrect")

	// ErrEmailNotVerified is returned when sign-in is attempted and email verification is strictly enforced.
	ErrEmailNotVerified = errors.New("emailpassword: email address has not been verified")

	// ErrPasswordTooShort is returned when a password does not satisfy the configured minimum length requirement.
	ErrPasswordTooShort = errors.New("emailpassword: password does not meet the minimum length requirement")

	// ErrPasswordTooLong is returned when a password exceeds the configured maximum length limit.
	ErrPasswordTooLong = errors.New("emailpassword: password exceeds the maximum allowed length")

	// ErrInvalidEmail is returned when an email format validation fails.
	ErrInvalidEmail = errors.New("emailpassword: invalid email address format")

	// ErrInvalidCredentials is returned when email lookup fails or password hash comparison does not match.
	ErrInvalidCredentials = errors.New("emailpassword: invalid credentials")

	// ErrInvalidParameter is returned when a required argument or parameter is missing or malformed.
	ErrInvalidParameter = errors.New("emailpassword: required parameter is missing or invalid")
)

// Repository defines the persistent storage contract required by the EmailPassword plugin.
// Implement this interface on your custom database adapter (e.g. PostgreSQL, MySQL, SQLite, MongoDB, GORM).
//
// # Implementation Example (GORM / database/sql):
//
//	type GormAuthRepository struct {
//		db *gorm.DB
//	}
//
//	func (r *GormAuthRepository) GetUserByEmail(ctx context.Context, email string) (*entity.User, error) {
//		var m UserModel
//		if err := r.db.WithContext(ctx).Where("email = ?", email).First(&m).Error; err != nil {
//			if errors.Is(err, gorm.ErrRecordNotFound) {
//				return nil, emailpassword.ErrUserNotFound
//			}
//			return nil, err
//		}
//		return m.ToEntity(), nil
//	}
//
//	func (r *GormAuthRepository) CreateUser(ctx context.Context, params *dto.CreateUserParams) (*entity.User, error) {
//		m := UserModel{
//			ID:           uuid.NewString(),
//			Email:        params.Email,
//			Name:         params.Name,
//			PasswordHash: params.PasswordHash,
//			CreatedAt:    time.Now(),
//			UpdatedAt:    time.Now(),
//		}
//		if err := r.db.WithContext(ctx).Create(&m).Error; err != nil {
//			return nil, err
//		}
//		return m.ToEntity(), nil
//	}
type Repository interface {
	// GetUserByEmail retrieves a user entity matching the provided unique email address.
	//
	// Function:
	//   Used during SignUp, SignIn, ForgotPassword, and SendVerificationEmail to check user existence and fetch profile details.
	//
	// Arguments:
	//   - ctx: Request cancellation and deadline context.
	//   - email: The normalized email address to query.
	//
	// Returns:
	//   - *entity.User: The matching user entity if found.
	//   - error: ErrUserNotFound if no record matches, or database error.
	//
	// Example SQL:
	//   SELECT id, email, name, email_verified, created_at, updated_at FROM users WHERE email = $1 LIMIT 1;
	GetUserByEmail(ctx context.Context, email string) (*entity.User, error)

	// GetUserByID retrieves a user entity matching the given unique identifier.
	//
	// Function:
	//   Used during ChangePassword, ResetPassword, VerifyPassword, and VerifyEmail flows.
	//
	// Arguments:
	//   - ctx: Request cancellation and deadline context.
	//   - id: The unique primary key identifier of the user (e.g. UUID).
	//
	// Returns:
	//   - *entity.User: The matching user entity.
	//   - error: ErrUserNotFound if no record matches, or database error.
	//
	// Example SQL:
	//   SELECT id, email, name, email_verified, created_at, updated_at FROM users WHERE id = $1 LIMIT 1;
	GetUserByID(ctx context.Context, id string) (*entity.User, error)

	// CreateUser persists a new user record generated from the provided registration parameters.
	//
	// Function:
	//   Called during SignUp to persist the primary user entity. Plugins may inspect or modify
	//   params.Extra before this method is called via EventSignUpBefore.
	//
	// Arguments:
	//   - ctx: Request cancellation and deadline context.
	//   - params: Pointer to CreateUserParams containing Email, Name, PasswordHash, and Extra metadata.
	//
	// Returns:
	//   - *entity.User: The newly created user entity with populated ID and timestamps.
	//   - error: ErrUserAlreadyExists on unique constraint violation, or database error.
	//
	// Example SQL:
	//   INSERT INTO users (id, email, name, password_hash, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6);
	CreateUser(ctx context.Context, params *dto.CreateUserParams) (*entity.User, error)

	// UpdateUser updates an existing user profile record in storage.
	//
	// Function:
	//   Used when updating user metadata, email verification state (email_verified = true), or profile attributes.
	//
	// Arguments:
	//   - ctx: Request cancellation and deadline context.
	//   - user: The updated user entity to persist.
	//
	// Returns:
	//   - error: Nil on success, ErrUserNotFound if the record is missing, or database error.
	//
	// Example SQL:
	//   UPDATE users SET email = $1, name = $2, email_verified = $3, updated_at = $4 WHERE id = $5;
	UpdateUser(ctx context.Context, user *entity.User) error

	// GetAccountByUserIDAndProvider retrieves the credential account associated with a user and authentication provider.
	//
	// Function:
	//   Used during SignIn, ChangePassword, and VerifyPassword to retrieve stored hashed passwords (provider: "credential").
	//
	// Arguments:
	//   - ctx: Request cancellation and deadline context.
	//   - userID: The target user's ID.
	//   - provider: The authentication provider identifier (typically "credential").
	//
	// Returns:
	//   - *entity.Account: The matching credentials account containing the password hash.
	//   - error: ErrAccountNotFound if no record matches, or database error.
	//
	// Example SQL:
	//   SELECT id, user_id, provider, password, created_at FROM accounts WHERE user_id = $1 AND provider = $2 LIMIT 1;
	GetAccountByUserIDAndProvider(ctx context.Context, userID, provider string) (*entity.Account, error)

	// CreateAccount persists a new provider credentials record associated with a user.
	//
	// Function:
	//   Called immediately after CreateUser during SignUp to link credential passwords to the user.
	//
	// Arguments:
	//   - ctx: Request cancellation and deadline context.
	//   - account: The credentials account entity to insert.
	//
	// Returns:
	//   - error: Nil on success, or database error on failure.
	//
	// Example SQL:
	//   INSERT INTO accounts (id, user_id, provider, password, created_at) VALUES ($1, $2, $3, $4, $5);
	CreateAccount(ctx context.Context, account *entity.Account) error

	// UpdateAccountPassword updates the hashed password for a specific account record.
	//
	// Function:
	//   Called during ChangePassword and ResetPassword to overwrite the stored password hash.
	//
	// Arguments:
	//   - ctx: Request cancellation and deadline context.
	//   - accountID: Primary key ID of the account record to update.
	//   - hashedPassword: The newly computed password hash.
	//
	// Returns:
	//   - error: Nil on success, ErrAccountNotFound if missing, or database error.
	//
	// Example SQL:
	//   UPDATE accounts SET password = $1, updated_at = $2 WHERE id = $3;
	UpdateAccountPassword(ctx context.Context, accountID, hashedPassword string) error

	// CreateVerificationToken persists a short-lived token record for password resets or email confirmations.
	//
	// Function:
	//   Called during ForgotPassword and SendVerificationEmail to save the generated token and expiration timestamp.
	//
	// Arguments:
	//   - ctx: Request cancellation and deadline context.
	//   - token: The VerificationToken entity (Identifier/Email, Token, ExpiresAt).
	//
	// Returns:
	//   - error: Nil on success, or database error on failure.
	//
	// Example SQL:
	//   INSERT INTO verification_tokens (identifier, token, expires_at) VALUES ($1, $2, $3);
	CreateVerificationToken(ctx context.Context, token *entity.VerificationToken) error

	// GetVerificationToken retrieves an active token record by its token string.
	//
	// Function:
	//   Called during ResetPassword and VerifyEmail to validate token existence and verify whether it has expired.
	//
	// Arguments:
	//   - ctx: Request cancellation and deadline context.
	//   - token: The raw token string submitted by the user.
	//
	// Returns:
	//   - *entity.VerificationToken: The matching token entity with its expiration timestamp.
	//   - error: ErrInvalidToken if no record is found, or database error.
	//
	// Example SQL:
	//   SELECT identifier, token, expires_at FROM verification_tokens WHERE token = $1 LIMIT 1;
	GetVerificationToken(ctx context.Context, token string) (*entity.VerificationToken, error)

	// DeleteVerificationToken removes a consumed or invalidated token from storage.
	//
	// Function:
	//   Called immediately upon successful password reset or email verification to guarantee single-use token consumption.
	//
	// Arguments:
	//   - ctx: Request cancellation and deadline context.
	//   - token: The token string to delete.
	//
	// Returns:
	//   - error: Nil on success, or database error on failure.
	//
	// Example SQL:
	//   DELETE FROM verification_tokens WHERE token = $1;
	DeleteVerificationToken(ctx context.Context, token string) error
}
