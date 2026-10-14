# Valkey Cache Adapter

The **Valkey Adapter** (`adapters/valkey`) provides a first-class cache and counter adapter for **Valkey**, the high-performance open-source continuation of Redis maintained under the Linux Foundation.

---

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth/adapters/valkey
```

---

## Usage

Because Valkey shares API compatibility with Redis protocols, the `adapters/valkey` adapter uses the same underlying connection mechanics with optimized aliases:

```go
package main

import (
    auth "github.com/BladiCreator/go-modular-auth"
    "github.com/BladiCreator/go-modular-auth/adapters/valkey"
)

func main() {
    // clientWrapper implements valkey.Client
    valkeyCache := valkey.New(clientWrapper)

    engine, err := auth.New(auth.Config{
        Store: myStore,
        Cache: valkeyCache,
    })
    if err != nil {
        panic(err)
    }

    _ = engine
}
```

---

## Why Valkey?

- **True Open Source (BSD-3-Clause)**: Maintained by the Linux Foundation.
- **Enhanced Performance**: Optimized multi-threaded I/O and reduced memory overhead under heavy concurrent session lookup traffic.
- **Drop-in Protocol**: Seamless compatibility with existing clusters and sentinels.
