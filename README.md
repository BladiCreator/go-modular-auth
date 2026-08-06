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
- 📢 **Bus de Eventos Reactivo Integrado**: Suscríbete a Hooks del ciclo de vida (`emailpassword.EventSignUpAfter`, `emailpassword.EventSignInAfter`, etc.) para enviar correos asíncronos, auditar accesos o notificar a Slack/Webhooks.
- 🔐 **Seguridad de Grado de Producción**: Hasheo de contraseñas con `bcrypt`, generación segura de tokens con `crypto/rand` y 2FA TOTP (RFC 6238).
- 🗄️ **Almacenamiento Desacoplado**: Conecta cualquier base de datos (**PostgreSQL**, **MySQL**, **SQLite**, **MongoDB**, **Redis**, **GORM**) implementando interfaces limpias. Incluye un adaptador multihilo en memoria de fábrica.

---

## 📦 Instalación

```bash
go get github.com/BladiCreator/go-modular-auth
```

---

## 💡 Ejemplo Práctico de Producción

A continuación se muestra un ejemplo completo que demuestra el registro de un usuario, suscripción a eventos de auditoría, inicio de sesión, generación de secreto 2FA (TOTP), verificación del código 2FA y validación activa de la sesión:

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
	"github.com/BladiCreator/go-modular-auth/domain/entity"
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

	// 2. Suscripción a eventos del EventBus para casos de uso reales
	app.Events().Subscribe(emailpassword.EventSignUpAfter, func(c context.Context, user *entity.User) {
		log.Printf("📧 [EVENTO] Enviando correo de bienvenida a: %s", user.Email)
	})

	app.Events().Subscribe(emailpassword.EventSignInAfter, func(c context.Context, user *entity.User, session *entity.Session) {
		log.Printf("🛡️ [AUDITORÍA] Login exitoso - Usuario ID: %s | IP: %s | Agent: %s",
			user.ID, session.IPAddress, session.UserAgent)
	})

	// 3. Flujo 1: Registro de un nuevo usuario
	fmt.Println("--- 1. Registro de Usuario ---")
	newUser, err := auth.Plugin[emailpassword.Plugin](app).SignUp(ctx, &dto.SignUp{
		Name:     "Carlos Mendoza",
		Email:    "carlos@empresa.com",
		Password: "PasswordSuperSegura123!",
	})
	if err != nil {
		log.Fatalf("Error en el registro: %v", err)
	}
	fmt.Printf("✔ Usuario Registrado: %s (ID: %s)\n\n", newUser.Name, newUser.ID)

	// 4. Flujo 2: Inicio de sesión (Creación de Sesión)
	fmt.Println("--- 2. Inicio de Sesión ---")
	user, session, err := auth.Plugin[emailpassword.Plugin](app).SignIn(ctx, &dto.SignIn{
		Email:    "carlos@empresa.com",
		Password: "PasswordSuperSegura123!",
	}, &dto.CreateSession{
		IPAddress: "192.168.1.50",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
	})
	if err != nil {
		log.Fatalf("Error en el login: %v", err)
	}
	fmt.Printf("✔ Autenticado como: %s\n", user.Email)
	fmt.Printf("✔ Token de Sesión: %s\n\n", session.Token)

	// 5. Flujo 3: Activación y Configuración de 2FA TOTP
	fmt.Println("--- 3. Configuración de 2FA TOTP ---")
	otpURI, err := auth.Plugin[twofactor.Plugin](app).GenerateTOTPSecret(ctx, user.ID)
	if err != nil {
		log.Fatalf("Error al generar 2FA: %v", err)
	}
	fmt.Printf("✔ URI para aplicación Authenticator: %s\n\n", otpURI)

	// 6. Flujo 4: Verificación del código 2FA ingresado por el usuario
	fmt.Println("--- 4. Verificación de Código 2FA ---")
	valid, err := auth.Plugin[twofactor.Plugin](app).VerifyCode(ctx, user.ID, "123456")
	if err != nil || !valid {
		fmt.Println("❌ Código 2FA inválido")
	} else {
		fmt.Println("✔ Código 2FA verificado exitosamente")
	}
	fmt.Println()

	// 7. Flujo 5: Validación activa de la sesión (Middleware HTTP)
	fmt.Println("--- 5. Validación de Token de Sesión ---")
	activeUser, activeSession, err := auth.Plugin[emailpassword.Plugin](app).ValidateSession(ctx, session.Token)
	if err != nil {
		log.Fatalf("Sesión inválida o expirada: %v", err)
	}
	fmt.Printf("✔ Sesión Activa perteneciente a: %s (Expira: %s)\n", activeUser.Email, activeSession.ExpiresAt)
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

func (r *GormAuthRepository) CreateUser(ctx context.Context, u *dto.SignUp) (*entity.User, error) {
	model := UserModel{
		ID:           uuid.New().String(),
		Name:         u.Name,
		Email:        u.Email,
		PasswordHash: u.Password,
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

func (r *GormAuthRepository) CreateSession(ctx context.Context, s *dto.CreateSessionContext) (*entity.Session, error) {
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

### 2. Inyección del Repositorio GORM en el Motor

```go
db, err := gorm.Open(postgres.Open("host=localhost user=postgres password=secret dbname=auth_db port=5432 sslmode=disable"))
if err != nil {
    log.Fatal(err)
}

gormRepo := store.NewGormAuthRepository(db)

app, err := auth.New(
    config.WithPlugins(
        plugins.EmailPassword(gormRepo, emailpassword.WithMinPasswordLength(10)),
        plugins.TwoFactor(gormRepo, twofactor.WithIssuer("MiAplicacion")),
    ),
)
```

---

## 📢 Casos de Uso Avanzados del EventBus

El Bus de Eventos decoupled permite reaccionar a cambios en el sistema sin acoplar la lógica de tu negocio dentro de la librería.

### 1. Envío Asíncrono de Correos de Bienvenida
```go
app.Events().Subscribe(emailpassword.EventSignUpAfter, func(ctx context.Context, user *entity.User) {
    // Ejecutar en goroutine asíncrona para no bloquear la respuesta HTTP
    go func(email, name string) {
        mailer.SendWelcomeEmail(email, name)
    }(user.Email, user.Name)
})
```

### 2. Auditoría de Seguridad & Detección de Inicios de Sesión Sospechosos
```go
app.Events().Subscribe(emailpassword.EventSignInAfter, func(ctx context.Context, user *entity.User, session *entity.Session) {
    if isUnknownIP(session.IPAddress) {
        securityLogger.Warn("Login desde ubicación desconocida", 
            "userID", user.ID, 
            "ip", session.IPAddress, 
            "userAgent", session.UserAgent,
        )
        notificationService.NotifyUserSecurityAlert(user.ID, session.IPAddress)
    }
})
```

---

## 🌐 Integración con Frameworks Web (ej. Gin / Fiber / Chi)

Puedes validar el token enviado en los encabezados HTTP `Authorization: Bearer <token>` mediante un middleware:

```go
func AuthMiddleware(app *auth.Auth) gin.HandlerFunc {
    return func(c *gin.Context) {
        authHeader := c.GetHeader("Authorization")
        if len(authHeader) < 8 || authHeader[:7] != "Bearer " {
            c.AbortWithStatusJSON(401, gin.H{"error": "Token no proporcionado"})
            return
        }

        token := authHeader[7:]
        user, session, err := auth.Plugin[emailpassword.Plugin](app).ValidateSession(c.Request.Context(), token)
        if err != nil {
            c.AbortWithStatusJSON(401, gin.H{"error": "Sesión inválida o expirada"})
            return
        }

        // Guardar datos en el contexto de la petición
        c.Set("currentUser", user)
        c.Set("currentSession", session)
        c.Next()
    }
}
```

---

## 🔌 Referencia Completa de Plugins

### 📧 Plugin `emailpassword`
Maneja el registro de usuarios, autenticación y sesiones.

- **Constructor**: `plugins.EmailPassword(repo, opts...)`
- **Opciones de Configuración**:
  - `emailpassword.WithMinPasswordLength(minLen int)` (defecto: `8`)
  - `emailpassword.WithSessionDuration(duration time.Duration)` (defecto: `7 días`)
- **Eventos emitidos**:
  - `emailpassword.EventSignUpBefore` → `(ctx context.Context, req *dto.SignUp)`
  - `emailpassword.EventSignUpAfter` → `(ctx context.Context, user *entity.User)`
  - `emailpassword.EventSignInBefore` → `(ctx context.Context, req *dto.SignIn)`
  - `emailpassword.EventSignInAfter` → `(ctx context.Context, user *entity.User, session *entity.Session)`

---

### 🔐 Plugin `twofactor`
Maneja la autenticación de 2 Factores mediante contraseñas temporales TOTP (RFC 6238).

- **Constructor**: `plugins.TwoFactor(repo, opts...)`
- **Opciones de Configuración**:
  - `twofactor.WithIssuer(issuer string)` (defecto: `"Auth"`)
- **Eventos emitidos**:
  - `twofactor.EventTOTPGenerated` → `(ctx context.Context, userID string, secret string)`

---

## 📄 Licencia

Este proyecto está liberado bajo la Licencia **MIT**. Consulta el archivo [LICENSE](LICENSE) para más información.
