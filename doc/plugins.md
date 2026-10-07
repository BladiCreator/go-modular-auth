# Plugin System

## 1. Principles of the Plugin System

GoModularAuth uses plugins to deliver capabilities that are not required for the minimal `User + Account + Credential + Session` core model.

> **Rule of Inclusion**:
> If a feature can be removed from an installation without breaking basic authentication, it belongs in a **Plugin**, not in the Core.

---

## 2. Plugin Modules vs Plugin Capabilities

To preserve architectural decoupling, GoModularAuth separates the **installable module** from the **consumed capability**:

```text
organizations.New()
        │
        ▼
   PluginModule (installed into Auth config)
        │
        ▼
 Plugin Registry (internal runtime)
        │
        ▼
plugins.Organization (consumed by application via auth.Get[T]())
```

- **`PluginModule`**: The concrete installer struct configuring dependencies, database tables, and hooks.
- **`PluginCapability`**: An interface or service exposed to consumer code.

---

## 3. Implementing a Plugin

A plugin module implements `auth.PluginModule`:

```go
type PluginModule interface {
    ID() string
    Init(host *Host) error
}
```

### Example: Organization Plugin
```go
package organization

import (
    "context"
    "github.com/BladiCreator/go-modular-auth/auth"
)

// Public Capability interface consumed by applications
type Capability interface {
    CreateOrganization(ctx context.Context, name string, ownerUserID string) (*Org, error)
}

type Module struct {
    customOption string
}

func New() *Module {
    return &Module{}
}

func (m *Module) ID() string {
    return "organization"
}

func (m *Module) Init(h *auth.Host) error {
    service := &orgService{
        auth:  h.Auth(),
        store: h.Store(),
        cache: h.Cache(),
    }

    // Register capability into the typed registry
    return auth.Provide[Capability](h, service)
}
```

---

## 4. Strongly Typed Consumption: `auth.Get[T]()`

Applications consume plugin capabilities in a type-safe manner without type casts:

```go
orgs, err := app.Get[organization.Capability]()
if err != nil {
    log.Fatalf("organization plugin not installed: %v", err)
}

org, err := orgs.CreateOrganization(ctx, "Acme Corp", currentUserID)
```

If a capability is mandatory during initialization, `app.MustGet[T]()` panics if missing:
```go
orgs := app.MustGet[organization.Capability]()
```

---

## 5. Dependencies and Topological Initialization

Plugins that require other plugins can declare dependencies via `auth.Dependent`:

```go
type Dependent interface {
    Dependencies() []string
}
```

When initializing plugins, GoModularAuth:
1. Detects missing dependencies and returns `auth.ErrPluginDependency`.
2. Detects dependency cycles and aborts.
3. Sorts modules topologically so dependencies are initialized **before** their dependents.

---

## 6. Hooks vs Events

Plugins extend engine behavior through two distinct mechanisms:

### 6.1 Workflow Hooks (`auth.Hooks`)
Hooks run **synchronously** during core operations:

- **`Before*` hooks** run *before* or *during* database transactions. They can mutate inputs or return an error to veto/abort the workflow.
  ```go
  h.Hooks().BeforeSignUp(func(ctx context.Context, in *auth.SignUpInput) error {
      if isDisposableEmail(in.Email) {
          return errors.New("disposable emails not permitted")
      }
      return nil
  })
  ```
- **`After*` hooks** run after successful database commit.

### 6.2 Observational Events (`auth.Events`)
Events run **asynchronously or observantly post-commit**. They cannot alter the workflow or roll back operations:

```go
h.Events().Subscribe(auth.EventUserCreated, func(ctx context.Context, e auth.Event) {
    user := e.Payload.(*user.User)
    auditLogger.Log("user_created", user.ID)
})
```
Any panics raised inside event handlers are safely recovered and logged, preventing background observers from breaking authentication flows.
