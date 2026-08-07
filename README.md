<p align="center">
  <img src="assets/logo.png" alt="Go Modular Auth Logo" width="200" />
</p>

<h1 align="center">Go Modular Auth</h1>

<p align="center">
  <strong>Un framework de autenticación modular, reactivo, extensible y fuertemente tipado para Go (Golang).</strong>
</p>

<p align="center">
  <a href="https://pkg.go.dev/github.com/BladiCreator/go-modular-auth"><img src="https://pkg.go.dev/badge/github.com/BladiCreator/go-modular-auth.svg" alt="Go Reference"></a>
  <a href="https://goreportcard.com/report/github.com/BladiCreator/go-modular-auth"><img src="https://goreportcard.com/badge/github.com/BladiCreator/go-modular-auth" alt="Go Report Card"></a>
  <a href="https://github.com/BladiCreator/go-modular-auth/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
  <a href="https://golang.org/"><img src="https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go" alt="Go Version"></a>
</p>

---

## 🌟 Visión General

**Go Modular Auth** es un motor de autenticación desacoplado diseñado para ofrecer la máxima flexibilidad y simplicidad a los desarrolladores de Go. Inspirado en arquitecturas modulares tipo *Better-Auth*, permite componer sistemas de autenticación mediante plugins independientes (`emailpassword`, `twofactor`, OAuth2, etc.) sin atar tu proyecto a ningún framework web específico (compatible con **Gin**, **Fiber**, **Echo**, **Chi**, **net/http** o **gRPC**).

---

## 🚀 Características Principales

- 🧩 **Arquitectura 100% Modular basada en Plugins**: Agrega o remueve características de autenticación según los requerimientos de tu proyecto.
- ⚡ **Tipado Fuerte mediante Genéricos (Go 1.18+)**: Acceso seguro a las APIs de cada plugin con autocompletado y sin casteos mediante `auth.Plugin[emailpassword.Plugin](app)`.
- 📦 **Patrón de Parámetros Mutables (`Params.Extra`)**: Permite a los plugins interceptar solicitudes durante el pipeline de eventos y adjuntar metadatos dinámicos (`Set`/`Get`) antes de persisitir en base de datos.
- 📢 **Bus de Eventos Reactivo Integrado**: Suscríbete a Hooks del ciclo de vida (`emailpassword.EventSignUpBefore`, `emailpassword.EventSignUpAfter`, etc.) para modificar datos en vuelo, enviar correos asíncronos o auditar accesos.
- 🔐 **Seguridad de Grado de Producción**: Hasheo de contraseñas con `bcrypt`, generación segura de tokens con `crypto/rand` y 2FA TOTP (RFC 6238).
- 🗄️ **Almacenamiento Desacoplado**: Conecta cualquier base de datos (**PostgreSQL**, **MySQL**, **SQLite**, **MongoDB**, **Redis**, **GORM**) implementando interfaces limpias. Incluye un adaptador multihilo en memoria de fábrica.

---

## 📦 Instalación

```bash
go get github.com/BladiCreator/go-modular-auth
```

---

## 💡 Ejemplo Práctico de Producción

A continuación se muestra un ejemplo completo que demuestra el registro de un usuario con interceptación de parámetros dinámicos, suscripción a eventos de auditoría, inicio de sesión, generación de secreto 2FA (TOTP) y verificación del código:

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/BladiCreator/go-modular-auth/adapters/memory"
	"github.com/BladiCreator/go-modular-auth/auth"
	"github.com/BladiCreator/go-modular-auth/config"
	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/plugins"
	"github.com/BladiCreator/go-modular-auth/plugins/emailpassword"
	"github.com/BladiCreator/go-modular-auth/plugins/twofactor"
)

func main() {
	ctx := context.Background()

	// Adaptador de almacenamiento (en memoria para este ejemplo)
	storage := memory.New()

	// 1. Inicialización del motor con configuración y plugins
	app, err := auth.New(
		config.WithBcryptCost(12),
		config.WithPlugins(
			plugins.EmailPassword(storage, emailpassword.WithMinPasswordLength(8)),
			plugins.TwoFactor(storage, twofactor.WithIssuer("Empresa ERP")),
		),
	)
	if err != nil {
		log.Fatalf("Error al inicializar Auth: %v", err)
	}

	// 2. Interceptación previa al registro para añadir datos dinámicos (Roles, Organizaciones, etc.)
	app.Events().Subscribe(emailpassword.EventSignUpBefore, func(c context.Context, payload *emailpassword.SignUpEventPayload) {
		payload.Params.Set("role", "admin")
		payload.Params.Set("org_id", "org_123")
	})

	// 3. Suscripción a eventos posteriores del EventBus
	app.Events().Subscribe(emailpassword.EventSignUpAfter, func(c context.Context, payload *emailpassword.SignUpEventPayload) {
		role, _ := payload.Params.Get("role")
		log.Printf("📧 [EVENTO] Enviando correo de bienvenida a: %s (Rol: %v)", payload.User.Email, role)
	})

	app.Events().Subscribe(emailpassword.EventSignInAfter, func(c context.Context, payload *emailpassword.SignInEventPayload) {
		log.Printf("🛡️ [AUDITORÍA] Login exitoso - Usuario ID: %s | Email: %s", payload.User.ID, payload.User.Email)
	})

	// 4. Flujo 1: Registro de un nuevo usuario
	fmt.Println("--- 1. Registro de Usuario ---")
	newUser, err := auth.Plugin[emailpassword.Plugin](app).SignUp(ctx, dto.SignUpParams{
		Name:     "Carlos Mendoza",
		Email:    "carlos@empresa.com",
		Password: "PasswordSuperSegura123!",
	})
	if err != nil {
		log.Fatalf("Error en el registro: %v", err)
	}
	fmt.Printf("✔ Usuario Registrado: %s (ID: %s)\n\n", newUser.Name, newUser.ID)

	// 5. Flujo 2: Inicio de sesión
	fmt.Println("--- 2. Inicio de Sesión ---")
	signedInUser, err := auth.Plugin[emailpassword.Plugin](app).SignIn(ctx, dto.SignInParams{
		Email:    "carlos@empresa.com",
		Password: "PasswordSuperSegura123!",
	})
	if err != nil {
		log.Fatalf("Error en el login: %v", err)
	}
	fmt.Printf("✔ Autenticado exitosamente como: %s (ID: %s)\n\n", signedInUser.Email, signedInUser.ID)

	// 6. Flujo 3: Configuración de 2FA TOTP
	fmt.Println("--- 3. Configuración de 2FA TOTP ---")
	otpURI, err := auth.Plugin[twofactor.Plugin](app).GenerateTOTPSecret(ctx, newUser.ID)
	if err != nil {
		log.Fatalf("Error al generar 2FA: %v", err)
	}
	fmt.Printf("✔ URI para aplicación Authenticator: %s\n\n", otpURI)

	// 7. Flujo 4: Verificación del código 2FA
	fmt.Println("--- 4. Verificación de Código 2FA ---")
	valid, err := auth.Plugin[twofactor.Plugin](app).VerifyCode(ctx, newUser.ID, "123456")
	if err != nil || !valid {
		fmt.Println("❌ Código 2FA inválido")
	} else {
		fmt.Println("✔ Código 2FA verificado exitosamente")
	}
}
```

---

## 🗄️ Repositorio Personalizado con Base de Datos Real (GORM + PostgreSQL)

En aplicaciones reales, querrás almacenar tus usuarios y sesiones en una base de datos relacional o de documentos. Para lograrlo, crea una estructura en tu proyecto que implemente las interfaces de los plugins requeridos.

### 1. Definición de Tablas/Modelos con GORM

```go
package store

import (
	"context"
	"errors"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain"
	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/plugins/emailpassword"
	"github.com/BladiCreator/go-modular-auth/plugins/twofactor"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Verificación de contratos en tiempo de compilación
var (
	_ emailpassword.Repository = (*GormAuthRepository)(nil)
	_ twofactor.Repository     = (*GormAuthRepository)(nil)
)

// Modelos ORM para GORM
type UserModel struct {
	ID            string    `gorm:"primaryKey;type:uuid"`
	Name          string    `gorm:"not null"`
	Email         string    `gorm:"uniqueIndex;not null"`
	PasswordHash  string    `gorm:"not null"`
	EmailVerified bool      `gorm:"default:false"`
	TOTPSecret    string    `gorm:"default:''"`
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type SessionModel struct {
	ID        string    `gorm:"primaryKey;type:uuid"`
	UserID    string    `gorm:"index;not null"`
	Token     string    `gorm:"uniqueIndex;not null"`
	IPAddress string
	UserAgent string
	ExpiresAt time.Time `gorm:"index"`
	CreatedAt time.Time
}

// Repositorio Principal
type GormAuthRepository struct {
	db *gorm.DB
}

func NewGormAuthRepository(db *gorm.DB) *GormAuthRepository {
	// AutoMigrate crea automáticamente las tablas en PostgreSQL
	_ = db.AutoMigrate(&UserModel{}, &SessionModel{})
	return &GormAuthRepository{db: db}
}

// --- Métodos de emailpassword.Repository ---

func (r *GormAuthRepository) CreateUser(ctx context.Context, params *dto.CreateUserParams) (*entity.User, error) {
	model := UserModel{
		ID:           uuid.New().String(),
		Name:         params.Name,
		Email:        params.Email,
		PasswordHash: params.PasswordHash,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	if err := r.db.WithContext(ctx).Create(&model).Error; err != nil {
		return nil, err
	}
	return toUserEntity(&model), nil
}

func (r *GormAuthRepository) GetUserByEmail(ctx context.Context, email string) (*entity.User, error) {
	var model UserModel
	err := r.db.WithContext(ctx).Where("email = ?", email).First(&model).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, domain.ErrUserNotFound
	}
	return toUserEntity(&model), err
}

func (r *GormAuthRepository) GetUserByID(ctx context.Context, id string) (*entity.User, error) {
	var model UserModel
	err := r.db.WithContext(ctx).Where("id = ?", id).First(&model).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, domain.ErrUserNotFound
	}
	return toUserEntity(&model), err
}

func (r *GormAuthRepository) CreateSession(ctx context.Context, s *dto.CreateSessionParams) (*entity.Session, error) {
	model := SessionModel{
		ID:        uuid.New().String(),
		UserID:    s.UserID,
		Token:     s.Token,
		IPAddress: s.IPAddress,
		UserAgent: s.UserAgent,
		ExpiresAt: s.ExpiresAt,
		CreatedAt: s.CreatedAt,
	}
	if err := r.db.WithContext(ctx).Create(&model).Error; err != nil {
		return nil, err
	}
	return toSessionEntity(&model), nil
}

func (r *GormAuthRepository) GetSessionByToken(ctx context.Context, token string) (*entity.Session, error) {
	var model SessionModel
	err := r.db.WithContext(ctx).Where("token = ?", token).First(&model).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, domain.ErrSessionNotFound
	}
	return toSessionEntity(&model), err
}

func (r *GormAuthRepository) DeleteSession(ctx context.Context, token string) error {
	return r.db.WithContext(ctx).Where("token = ?", token).Delete(&SessionModel{}).Error
}

// --- Métodos de twofactor.Repository ---

func (r *GormAuthRepository) SaveTOTPSecret(ctx context.Context, userID string, secret string) error {
	return r.db.WithContext(ctx).Model(&UserModel{}).Where("id = ?", userID).Update("totp_secret", secret).Error
}

func (r *GormAuthRepository) GetTOTPSecret(ctx context.Context, userID string) (string, error) {
	var model UserModel
	err := r.db.WithContext(ctx).Select("totp_secret").Where("id = ?", userID).First(&model).Error
	if errors.Is(err, gorm.ErrRecordNotFound) || model.TOTPSecret == "" {
		return "", domain.ErrTOTPNotFound
	}
	return model.TOTPSecret, nil
}

// Helpers de conversión Mappings
func toUserEntity(m *UserModel) *entity.User {
	return &entity.User{
		ID:            m.ID,
		Name:          m.Name,
		Email:         m.Email,
		PasswordHash:  m.PasswordHash,
		EmailVerified: m.EmailVerified,
		CreatedAt:     m.CreatedAt,
		UpdatedAt:     m.UpdatedAt,
	}
}

func toSessionEntity(m *SessionModel) *entity.Session {
	return &entity.Session{
		ID:        m.ID,
		UserID:    m.UserID,
		Token:     m.Token,
		ExpiresAt: m.ExpiresAt,
		CreatedAt: m.CreatedAt,
		IPAddress: m.IPAddress,
		UserAgent: m.UserAgent,
	}
}
```

---

## 📢 Casos de Uso Avanzados del EventBus y Parámetros Mutables

El Bus de Eventos decoupled permite interceptar y modificar datos en vuelo durante el flujo de registro o reaccionar de forma asíncrona tras completar las acciones.

### 1. Interceptación y Modificación de Parámetros de Registro (`Params.Set`)
```go
app.Events().Subscribe(emailpassword.EventSignUpBefore, func(ctx context.Context, payload *emailpassword.SignUpEventPayload) {
    // Añadir atributos de plugins (ej. Organización o Rol inicial)
    payload.Params.Set("organization_id", "org_987")
    payload.Params.Set("role", "member")
})
```

### 2. Envío Asíncrono de Correos de Bienvenida
```go
app.Events().Subscribe(emailpassword.EventSignUpAfter, func(ctx context.Context, payload *emailpassword.SignUpEventPayload) {
    // Ejecutar en goroutine asíncrona para no bloquear la respuesta HTTP
    go func(user *entity.User) {
        mailer.SendWelcomeEmail(user.Email, user.Name)
    }(payload.User)
})
```

### 3. Auditoría de Seguridad en Inicios de Sesión
```go
app.Events().Subscribe(emailpassword.EventSignInAfter, func(ctx context.Context, payload *emailpassword.SignInEventPayload) {
    securityLogger.Info("Login exitoso", "userID", payload.User.ID, "email", payload.User.Email)
})
```

---

## 🔌 Referencia Completa de Plugins

### 📧 Plugin `emailpassword`
Maneja el registro de usuarios, autenticación y contraseñas.

- **Constructor**: `plugins.EmailPassword(repo, opts...)`
- **Opciones de Configuración**:
  - `emailpassword.WithMinPasswordLength(minLen int)` (defecto: `8`)
  - `emailpassword.WithRequireEmailVerification(require bool)` (defecto: `false`)
  - `emailpassword.WithResetTokenExpiry(duration time.Duration)` (defecto: `1 hora`)
- **Eventos emitidos**:
  - `emailpassword.EventSignUpBefore` → `(ctx context.Context, payload *emailpassword.SignUpEventPayload)` (posee `Params *dto.CreateUserParams`)
  - `emailpassword.EventSignUpAfter` → `(ctx context.Context, payload *emailpassword.SignUpEventPayload)` (posee `Params` y `User *entity.User`)
  - `emailpassword.EventSignInBefore` → `(ctx context.Context, payload *emailpassword.SignInEventPayload)` (posee `User *entity.User`)
  - `emailpassword.EventSignInAfter` → `(ctx context.Context, payload *emailpassword.SignInEventPayload)` (posee `User *entity.User`)
  - `emailpassword.EventPasswordChangeBefore` / `After` → `(ctx context.Context, payload *emailpassword.PasswordChangeEventPayload)`
  - `emailpassword.EventPasswordResetRequested` → `(ctx context.Context, payload *emailpassword.PasswordResetRequestedEventPayload)`
  - `emailpassword.EventPasswordResetCompleted` → `(ctx context.Context, payload *emailpassword.PasswordResetCompletedEventPayload)`

---

### 🔐 Plugin `twofactor`
Maneja la autenticación de 2 Factores mediante contraseñas temporales TOTP (RFC 6238).

- **Constructor**: `plugins.TwoFactor(repo, opts...)`
- **Opciones de Configuración**:
  - `twofactor.WithIssuer(issuer string)` (defecto: `"Auth"`)
- **Eventos emitidos**:
  - `twofactor.EventTOTPGenerated` → `(ctx context.Context, payload *twofactor.TOTPGeneratedEventPayload)`

---

## 📄 Licencia

Este proyecto está liberado bajo la Licencia **MIT**. Consulta el archivo [LICENSE](LICENSE) para más información.
