# SAML 2.0 Identity Provider (IdP) Plugin

The **SAML Provider Plugin** (`plugins/saml-provider`) turns your GoModularAuth application into a **SAML 2.0 Identity Provider (IdP)**. It registers external Service Providers (SPs), serves IdP metadata XML, and signs assertion responses for single sign-on into enterprise applications.

---

## 1. Problem Solved

Enterprises often require their internal identity system to act as the primary SAML 2.0 IdP for third-party SaaS tools (AWS IAM Identity Center, Salesforce, Zendesk, Datadog). The `saml-provider` plugin handles:
- **Service Provider Registration**: Managing relying party Entity IDs, Assertion Consumer Service (ACS) URLs, and certificates.
- **IdP Metadata XML Generation**: Generating the standard FederationMetadata XML document.
- **Cryptographic Assertion Signing**: Building and signing SAML 2.0 `<Response>` and `<Assertion>` XML payloads with XML-DSIG.

---

## 2. Installation & Registration

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/saml-provider
```

Register the plugin:

```go
package main

import (
    auth "github.com/BladiCreator/go-modular-auth"
    samlprovider "github.com/BladiCreator/go-modular-auth/plugins/saml-provider"
)

func main() {
    samlIdPMod := samlprovider.New(
        samlprovider.WithEntityID("https://auth.example.com/saml/idp"),
        samlprovider.WithSSOURL("https://auth.example.com/saml/sso"),
        samlprovider.WithCertificate(x509CertPEM),
        samlprovider.WithPrivateKey(rsaPrivateKey),
    )

    engine, err := auth.New(auth.Config{
        Adapter: adaptermem.New(),
        Plugins: []auth.PluginModule{samlIdPMod},
    })
    if err != nil {
        panic(err)
    }

    // Resolve capability
    idp := auth.MustGet[samlprovider.SAMLProvider](engine)
    _ = idp
}
```

---

## 3. Capability Interface: `samlprovider.SAMLProvider`

```go
type SAMLProvider interface {
    GetMetadata() ([]byte, error)
    RegisterSP(sp *ServiceProvider) error
    GetSP(entityID string) (*ServiceProvider, error)
    BuildResponse(ctx context.Context, spEntityID string, u *user.User, inResponseTo string) (string, error)
}
```

---

## 4. Usage

### 4.1 Registering an External Service Provider (SP)
```go
err := idp.RegisterSP(&samlprovider.ServiceProvider{
    EntityID: "https://signin.aws.amazon.com/saml",
    ACSURL:   "https://signin.aws.amazon.com/saml",
})
```

### 4.2 Serving IdP Metadata
```go
http.HandleFunc("/saml/metadata.xml", func(w http.ResponseWriter, r *http.Request) {
    xmlBytes, err := idp.GetMetadata()
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    w.Header().Set("Content-Type", "application/xml; charset=utf-8")
    w.Write(xmlBytes)
})
```

### 4.3 Generating SAML Assertion Responses
```go
// Build Base64-encoded signed SAMLResponse
samlResponseB64, err := idp.BuildResponse(ctx, "https://signin.aws.amazon.com/saml", user, samlRequestID)
// Return via SAML HTTP POST binding HTML form to client browser
```
