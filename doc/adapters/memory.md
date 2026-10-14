# In-Memory Adapters (Testing & Local Development)

The **In-Memory Adapters** package (`adapters/memory`) provides lightweight, thread-safe implementations of all infrastructure contracts: `adapter.Adapter`, `cache.Cache`, and `email.Sender`.

---

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth/adapters/memory
```

---

## Usage

```go
package main

import (
    auth "github.com/BladiCreator/go-modular-auth"
    "github.com/BladiCreator/go-modular-auth/adapters/memory"
)

func main() {
    // In-memory Database Adapter
    memAdapter := memory.NewAdapter()

    // In-memory Cache
    memCache := memory.NewCache()

    // In-memory Email Sender
    memEmail := memory.NewEmail()

    engine, err := auth.New(auth.Config{
        Adapter: memAdapter,
        Cache:   memCache,
        Email:   memEmail,
    })
    if err != nil {
        panic(err)
    }

    _ = engine
}
```

---

## Component Details

### 1. In-Memory Database Adapter (`adapter.Adapter`)
- Dynamic multi-model storage supporting dynamic schema registration and model extension.
- Thread-safe with snapshot isolation for atomic rollbacks (`Transaction`).
- Supports comparison operators (`Eq`, `Ne`, `Gt`, `Gte`, `Lt`, `Lte`, `In`, `IsNull`, `IsNotNull`).

### 2. In-Memory Cache (`cache.Cache`)
- Thread-safe key-value cache with background eviction of expired keys.
- Implements `cache.Counter` for rate-limiting simulation.

### 3. In-Memory Email Mock (`email.Sender`)
- Records all sent `email.Message` payloads in an internal slice.
- Perfect for unit test assertions (verifying that verification tokens or reset links were properly generated).
