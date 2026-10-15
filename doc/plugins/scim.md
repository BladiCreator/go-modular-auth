# SCIM 2.0 Provisioning Plugin

The **SCIM Plugin** (`plugins/scim`) implements **System for Cross-domain Identity Management (SCIM 2.0)** per RFC 7643 and RFC 7644. It enables enterprise IT departments to automatically provision, update, and de-provision users and groups directly from corporate identity providers (Okta, Microsoft Entra ID / Azure AD, OneLogin, PingFederate).

---

## 1. Problem Solved

Enterprises require centralized employee lifecycle management. When an employee is hired or leaves a company, their access must be granted or revoked across all SaaS tools automatically without manual intervention.

The `scim` plugin provides:
- **SCIM 2.0 `/Users` Endpoint**: Automatic user onboarding, attribute synchronization, and de-provisioning.
- **SCIM 2.0 `/Groups` Endpoint**: Automated team membership synchronization.
- **Core User Synchronization**: Automatically persists provisioned users into GoModularAuth Core `User` tables.

---

## 2. Installation & Registration

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/scim
```

Register the plugin:

```go
package main

import (
    auth "github.com/BladiCreator/go-modular-auth"
    "github.com/BladiCreator/go-modular-auth/plugins/scim"
)

func main() {
    scimMod := scim.New()

    engine, err := auth.New(auth.Config{
        Adapter: adaptermem.New(),
        Plugins: []auth.PluginModule{scimMod},
    })
    if err != nil {
        panic(err)
    }

    // Resolve capability
    scimProvider := auth.MustGet[scim.SCIMProvider](engine)
    _ = scimProvider
}
```

---

## 3. Capability Interface: `scim.SCIMProvider`

```go
type SCIMProvider interface {
    CreateUser(ctx context.Context, res *v2.UserResource) (*v2.UserResource, error)
    GetUser(ctx context.Context, id string) (*v2.UserResource, error)
    UpdateUser(ctx context.Context, res *v2.UserResource) (*v2.UserResource, error)
    DeleteUser(ctx context.Context, id string) error
    ListUsers(ctx context.Context, startIndex, count int) (*v2.ListResponse, error)

    CreateGroup(ctx context.Context, res *v2.GroupResource) (*v2.GroupResource, error)
    GetGroup(ctx context.Context, id string) (*v2.GroupResource, error)
    UpdateGroup(ctx context.Context, res *v2.GroupResource) (*v2.GroupResource, error)
    DeleteGroup(ctx context.Context, id string) error
    ListGroups(ctx context.Context, startIndex, count int) (*v2.ListResponse, error)
}
```

---

## 4. Usage

### 4.1 Creating a SCIM User
```go
createdUser, err := scimProvider.CreateUser(ctx, &v2.UserResource{
    UserName: "jane.doe@example.com",
    Name: &v2.Name{
        GivenName:  "Jane",
        FamilyName: "Doe",
    },
    Emails: []v2.Email{
        {Value: "jane.doe@example.com", Primary: true},
    },
    Active: true,
})
```

### 4.2 Updating / Disabling an Employee
When an employee departs the company, Okta sends a de-provision request (`active: false`):

```go
existingUser, _ := scimProvider.GetUser(ctx, scimUserID)
existingUser.Active = false
updated, err := scimProvider.UpdateUser(ctx, existingUser)
```

### 4.3 Group Membership Synchronization
```go
group, err := scimProvider.CreateGroup(ctx, &v2.GroupResource{
    DisplayName: "Security Engineers",
    Members: []v2.Member{
        {Value: createdUser.ID, Display: "Jane Doe"},
    },
})
```
