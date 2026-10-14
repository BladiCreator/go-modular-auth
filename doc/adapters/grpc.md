# gRPC Transport Adapter

The **gRPC Adapter** (`adapters/grpc`) provides unary and streaming server interceptors to authenticate RPC calls and inject the authenticated `Principal` and `Session` into gRPC handler contexts.

---

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth/adapters/grpc
```

---

## Metadata Token Extractors

Extractors read credentials from incoming gRPC `metadata.MD`:

```go
import "github.com/BladiCreator/go-modular-auth/adapters/grpc"

// Extracts Bearer token from the incoming "authorization" metadata key
extractor := grpc.BearerMetadataExtractor
```

Custom extractors can be provided:

```go
customExtractor := func(md metadata.MD) string {
    vals := md.Get("x-custom-token")
    if len(vals) > 0 {
        return vals[0]
    }
    return ""
}
```

---

## Server Interceptors

Configure interceptors when creating your `*grpc.Server`:

```go
package main

import (
    "google.golang.org/grpc"

    auth "github.com/BladiCreator/go-modular-auth"
    authgrpc "github.com/BladiCreator/go-modular-auth/adapters/grpc"
)

func NewServer(engine *auth.Auth) *grpc.Server {
    server := grpc.NewServer(
        // Unary RPC Interceptor
        grpc.UnaryInterceptor(authgrpc.UnaryServerInterceptor(engine,
            authgrpc.WithExtractor(authgrpc.BearerMetadataExtractor),
            authgrpc.WithLenient(false), // Strict: returns codes.Unauthenticated if missing/invalid
        )),
        // Streaming RPC Interceptor
        grpc.StreamInterceptor(authgrpc.StreamServerInterceptor(engine,
            authgrpc.WithExtractor(authgrpc.BearerMetadataExtractor),
            authgrpc.WithLenient(false),
        )),
    )

    return server
}
```

### Options
- `WithExtractor(MetadataExtractor)`: Configures the metadata extractor function.
- `WithLenient(bool)`: When `true`, unauthenticated requests proceed without raising an error. When `false` (default), unauthenticated requests fail immediately with `codes.Unauthenticated`.

---

## Accessing Credentials in RPC Handlers

```go
func (s *UserServer) GetProfile(ctx context.Context, req *pb.GetProfileRequest) (*pb.ProfileResponse, error) {
    // 1. Retrieve authenticated Principal
    principal, ok := authgrpc.PrincipalFrom(ctx)
    if !ok {
        return nil, status.Error(codes.Unauthenticated, "unauthenticated")
    }

    // 2. Retrieve underlying SessionResult
    sessionResult, _ := authgrpc.SessionFrom(ctx)

    return &pb.ProfileResponse{
        UserId: principal.Subject,
        Email:  sessionResult.User.Email,
    }, nil
}
```
