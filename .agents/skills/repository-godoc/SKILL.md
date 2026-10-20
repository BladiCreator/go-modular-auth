---
name: repository-godoc
description: >-
  Estándar y guía paso a paso para escribir la documentación GoDoc de archivos repository.go en go-modular-auth.
  Usar al crear nuevos plugins, refactorizar repositorios existentes o agregar comentarios GoDoc a interfaces y métodos Repository.
---

# Estándar de Documentación GoDoc para Persistencia y Repositorios

En `go-modular-auth`, la persistencia se gestiona en dos niveles arquitectónicos desacoplados:
1. **Contratos Core (`store.Store`)**: Persistencia de identidades principales (`Users`, `Accounts`, `Credentials`, `Sessions`, `Tokens`).
2. **Modelos Esquematizados de Plugins (`plugin-sdk.Model[T]`)**: Los plugins declaran modelos (`schema.Model`) y operan sobre el adaptador genérico mediante `*sdk.Repository[T]`.

Cuando se definen interfaces de repositorio específicas, contratos de persistencia de plugins o adaptadores de base de datos personalizados (GORM, PostgreSQL, MySQL, Redis, MongoDB, SurrealDB), **todos los contratos de persistencia deben cumplir estrictamente con el siguiente estándar de GoDoc**.

---

## 1. Estructura General del Contrato de Persistencia

Un contrato de persistencia estándar se compone de las siguientes secciones documentadas:

1. **Constantes / Errores Sentinela (`var (...)`)** con comentarios individuales.
2. **Interfaz de Persistencia / Repositorio (Cabecera + Ejemplo GORM / SQL + Recomendación de Caché opcional)**
3. **Métodos de la Interfaz (Documentación Estructurada en 5+ Secciones: Function, Storage, Arguments, Returns, Example SQL)**
4. **Implementación In-Memory y sus Métodos Documentados**

---

## 2. Documentación de Cabecera de la Interfaz


La cabecera del tipo `type Repository interface` debe explicar qué entidad persiste la interfaz y proveer ejemplos ejecutables. Para consultas de **alta frecuencia** (ej: validación de tokens Bearer, sesiones, JWKS), debe incluir la recomendación de estrategia **Cache-Aside (Redis)**.

### Plantilla de Cabecera:

```go
// Repository defines the persistent storage contract required by the <NombrePlugin> plugin.
// Implement this interface on your custom database adapter (e.g. PostgreSQL, MySQL, SQLite, MongoDB, GORM, Redis).
//
// # Implementation Example (GORM / database/sql):
//
//	type Gorm<NombrePlugin>Repository struct {
//		db *gorm.DB
//	}
//
//	func (r *Gorm<NombrePlugin>Repository) <MetodoPrincipal>(ctx context.Context, <param> string) (*<Entity>, error) {
//		var entity <Entity>
//		if err := r.db.WithContext(ctx).Where("<columna> = ?", <param>).First(&entity).Error; err != nil {
//			if errors.Is(err, gorm.ErrRecordNotFound) {
//				return nil, <plugin>.Err<Entity>NotFound
//			}
//			return nil, err
//		}
//		return &entity, nil
//	}
//
// # Storage and Caching Recommendation (Redis / Cache-Aside Strategy):
//
// Because `<MetodoPrincipal>` is invoked on **every authenticated API request**, querying
// the relational database on every HTTP call can become a performance bottleneck.
// Decorating your database repository with Redis or an in-memory Cache-Aside wrapper is strongly recommended:
//
//	type Cached<NombrePlugin>Repository struct {
//		dbRepo <plugin>.Repository
//		redis  *redis.Client
//		ttl    time.Duration
//	}
//
//	func (r *Cached<NombrePlugin>Repository) <MetodoPrincipal>(ctx context.Context, key string) (*<Entity>, error) {
//		cacheKey := "<prefix>:" + key
//		val, err := r.redis.Get(ctx, cacheKey).Bytes()
//		if err == nil {
//			var entity <Entity>
//			if json.Unmarshal(val, &entity) == nil {
//				return &entity, nil // Fast Cache Hit ($O(1)$)
//			}
//		}
//		entity, err := r.dbRepo.<MetodoPrincipal>(ctx, key)
//		if err != nil {
//			return nil, err
//		}
//		bytes, _ := json.Marshal(entity)
//		r.redis.Set(ctx, cacheKey, bytes, r.ttl)
//		return entity, nil
//	}
type Repository interface {
```

---

## 3. Documentación Estructurada para Métodos de `Repository`

**Cada método** dentro de `Repository` DEBE incluir los siguientes bloques comentados:

1. **Línea de Resumen**: Acción concisa del método.
2. **`Function:`**: Explica dónde, cuándo y por qué se ejecuta en la API/Eventos.
3. **`Storage:`**: Especifica si es `Database (GORM / SQL)`, `Cache (Redis / In-Memory TTL)`, o `Both (Cache-Aside Strategy)`.
4. **`Arguments:`**: Lista viñeteada de parámetros con `ctx`.
5. **`Returns:`**: Lista de valores retornados y errores centinela.
6. **`Example SQL:`**: Consulta SQL recomendada (en mayúsculas con `$1, $2`).
7. **`Example Cache (Redis):`** *(Opcional para métodos con caché)*: Comando Redis equivalente.

### Plantilla de Método:

```go
	// <NombreMetodo> <descripción corta de la acción>.
	//
	// Function:
	//   <Caso de uso durante la petición o ciclo de vida>.
	//
	// Storage:
	//   Both (Cache-Aside Strategy) - <Búsqueda de alta frecuencia en caché/relacional>.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - <arg>: <Descripción del parámetro>.
	//
	// Returns:
	//   - <Retorno>: <Descripción del valor retornado>.
	//   - error: <ErrorCentinela> si no existe, o error de infraestructura.
	//
	// Example SQL:
	//   SELECT id, token, expires_at FROM sessions WHERE token = $1 LIMIT 1;
	//
	// Example Cache (Redis):
	//   val, err := rdb.Get(ctx, "session:" + token).Bytes()
	<NombreMetodo>(ctx context.Context, <arg> <Tipo>) (<Retorno>, error)
```

---

## 4. Ejemplos Reales de Referencia

### Ejemplo 1: `plugins/bearer/repository.go` (Patrón con Caché Redis)

```go
// Repository defines the persistent storage contract required by the Bearer plugin to look up active sessions.
// Implement this interface on your custom database adapter (e.g. PostgreSQL, MySQL, MongoDB, GORM, Redis).
//
// # Implementation Example (GORM / database/sql):
//
//	type GormBearerRepository struct {
//		db *gorm.DB
//	}
//
//	func (r *GormBearerRepository) GetSessionByToken(ctx context.Context, token string) (*entity.Session, error) {
//		var s entity.Session
//		if err := r.db.WithContext(ctx).Where("token = ?", token).First(&s).Error; err != nil {
//			if errors.Is(err, gorm.ErrRecordNotFound) {
//				return nil, bearer.ErrSessionNotFound
//			}
//			return nil, err
//		}
//		return &s, nil
//	}
//
// # Storage and Caching Recommendation (Redis / Cache-Aside Strategy):
//
// Because `GetSessionByToken` is invoked on **every Bearer-authenticated API request**, querying
// the relational database on every HTTP call can become a performance bottleneck.
// Decorating your database repository with Redis or an in-memory Cache-Aside wrapper is strongly recommended:
//
//	type CachedBearerRepository struct {
//		dbRepo bearer.Repository
//		redis  *redis.Client
//		ttl    time.Duration
//	}
//
//	func (r *CachedBearerRepository) GetSessionByToken(ctx context.Context, token string) (*entity.Session, error) {
//		cacheKey := "session:" + token
//		val, err := r.redis.Get(ctx, cacheKey).Bytes()
//		if err == nil {
//			var sess entity.Session
//			if json.Unmarshal(val, &sess) == nil {
//				return &sess, nil // Fast Cache Hit ($O(1)$ response)
//			}
//		}
//		sess, err := r.dbRepo.GetSessionByToken(ctx, token)
//		if err != nil {
//			return nil, err
//		}
//		bytes, _ := json.Marshal(sess)
//		r.redis.Set(ctx, cacheKey, bytes, r.ttl)
//		return sess, nil
//	}
type Repository interface {
	// GetSessionByToken retrieves an active session by its raw token identifier.
	//
	// Function:
	//   Queries storage for the session entity associated with the verified raw token string.
	//
	// Storage:
	//   Both (Cache-Aside Strategy) - High-frequency lookup per HTTP request.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - token: Raw session token string (unstripped of HMAC signature).
	//
	// Returns:
	//   - *entity.Session: Active session entity if found.
	//   - error: ErrSessionNotFound if not found, or infrastructure error.
	//
	// Example SQL:
	//   SELECT id, user_id, token, expires_at, created_at, ip_address, user_agent FROM sessions WHERE token = $1 LIMIT 1;
	//
	// Example Cache (Redis):
	//   val, err := rdb.Get(ctx, "session:" + token).Bytes()
	GetSessionByToken(ctx context.Context, token string) (*entity.Session, error)
}
```

---

## 5. Checklist de Verificación de Repositorios

- [ ] Comentarios GoDoc en todos los errores centinela (`var (...)`).
- [ ] Cabecera de `Repository` con `# Implementation Example (GORM / database/sql)`.
- [ ] En endpoints de alta frecuencia, cabecera con `# Storage and Caching Recommendation (Redis / Cache-Aside Strategy)`.
- [ ] Cada método con bloques `Function:`, `Storage:`, `Arguments:`, `Returns:`.
- [ ] Cada método con bloque `Example SQL:` (y opcionalmente `Example Cache (Redis):`).
- [ ] `MemoryRepository` y sus métodos exported completamente documentados.
