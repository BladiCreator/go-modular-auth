# GoModularAuth Adapters

This directory contains comprehensive usage guides for all official infrastructure and transport adapters supported by **GoModularAuth**.

---

## Adapter Taxonomy

Adapters bridge GoModularAuth to external systems, drivers, protocols, and network transports. The core engine never imports drivers or frameworks directly; it relies on these adapters to satisfy its interface contracts.

```text
                                GoModularAuth Core
                                         │
        ┌───────────────────┬────────────┴────────────┬───────────────────┐
        │                   │                         │                   │
 Transport Adapters  Database Adapters         Cache Adapters      Email Adapters
        │                   │                         │                   │
  ┌─────┴─────┐       ┌─────┴─────┐             ┌─────┴─────┐       ┌─────┴─────┐
  │ HTTP      │       │ Postgres  │             │ Redis     │       │ SMTP      │
  │ gRPC      │       │ SQLite    │             │ Valkey    │       │ Memory    │
  │ Fiber     │       │ MySQL     │             │ Memory    │       └───────────┘
  └───────────┘       │ Memory    │             └───────────┘
                      └───────────┘
```

---

## Adapters Index

### 1. Transport Adapters
- [**HTTP Adapter** (`http.md`)](http.md): Standard `net/http` middlewares (`Authenticate`, `RequireSession`), token extractors (Bearer, Cookies, Headers), context propagation, and integration recipes for Chi, Gin, Echo, and Fiber.
- [**gRPC Adapter** (`grpc.md`)](grpc.md): Unary and streaming gRPC server interceptors, metadata token extraction, and context-bound `Principal` propagation.

### 2. Database Adapters (`adapter.Adapter`)
- [**PostgreSQL Adapter** (`postgres.md`)](postgres.md): Production PostgreSQL database adapter using `database/sql`, dynamic DDL migrations, connection pooling, and `sqltx` atomic transaction propagation.
- [**SQLite Adapter** (`sqlite.md`)](sqlite.md): Production SQLite database adapter supporting WAL mode, busy timeout handlers, and dynamic schemas.
- [**MySQL Adapter** (`mysql.md`)](mysql.md): Production MySQL 8.0+ database adapter with index constraints and connection pooling.
- [**In-Memory Adapter** (`memory.md#database`)](memory.md#1-in-memory-database-adapter-adapteradapter): Thread-safe in-memory adapter with snapshot rollback for unit and integration tests.

### 3. Cache & Ephemeral Adapters (`cache.Cache` & `cache.Counter`)
- [**Redis Adapter** (`redis.md`)](redis.md): Distributed Redis cache with TTL eviction and atomic counter incrementation for rate limiting.
- [**Valkey Adapter** (`valkey.md`)](valkey.md): High-performance Valkey cache adapter (open-source Redis continuation).
- [**In-Memory Cache** (`memory.md#cache`)](memory.md#2-in-memory-cache-cachecache): Thread-safe in-memory cache with TTL cleanup and atomic counter support.

### 4. Transactional Email Adapters (`email.Sender`)
- [**SMTP Adapter** (`smtp.md`)](smtp.md): Production SMTP sender supporting TLS, STARTTLS, PLAIN auth, and multipart/alternative MIME formatting.
- [**In-Memory Mock Email** (`memory.md#email`)](memory.md#3-in-memory-email-mock-emailsender): In-memory sender capturing sent messages for test assertions.
