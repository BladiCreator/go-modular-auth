package sso_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapter/memory"
	corecache "github.com/BladiCreator/go-modular-auth/cache/memory"
	organizations "github.com/BladiCreator/go-modular-auth/plugins/organizations"
	sso "github.com/BladiCreator/go-modular-auth/plugins/sso"
	"github.com/BladiCreator/go-modular-auth/plugins/sso/oidc"
	"github.com/BladiCreator/go-modular-auth/plugins/sso/plugins"
)

type mockIdPServer struct {
	server     *httptest.Server
	privateKey *rsa.PrivateKey
	issuer     string
	keyID      string
	clientID   string
}

func newMockIdPServer(t *testing.T, clientID string) *mockIdPServer {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}

	mock := &mockIdPServer{
		privateKey: privKey,
		keyID:      "idp-key-1",
		clientID:   clientID,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		doc := oidc.DiscoveryDocument{
			Issuer:                mock.issuer,
			AuthorizationEndpoint: mock.issuer + "/auth",
			TokenEndpoint:         mock.issuer + "/token",
			JWKSUri:               mock.issuer + "/jwks",
		}
		_ = json.NewEncoder(w).Encode(doc)
	})

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		pub := &privKey.PublicKey
		nStr := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
		eBytes := big.NewInt(int64(pub.E)).Bytes()
		eStr := base64.RawURLEncoding.EncodeToString(eBytes)

		jwks := oidc.JWKS{
			Keys: []oidc.JWK{
				{
					Kty: "RSA",
					Kid: mock.keyID,
					Alg: "RS256",
					N:   nStr,
					E:   eStr,
				},
			},
		}
		_ = json.NewEncoder(w).Encode(jwks)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		code := r.Form.Get("code")

		sub := "okta_sub_123"
		email := "alice@acme.com"
		nonce := code
		if strings.Contains(code, ":") {
			parts := strings.Split(code, ":")
			code = parts[0]
			nonce = parts[1]
		}

		now := time.Now().UTC()
		headerBytes, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": mock.keyID})
		claimsBytes, _ := json.Marshal(map[string]any{
			"iss":   mock.issuer,
			"sub":   sub,
			"aud":   mock.clientID,
			"exp":   now.Add(time.Hour).Unix(),
			"iat":   now.Unix(),
			"nonce": nonce,
			"email": email,
			"name":  "Alice Acme",
		})

		input := base64.RawURLEncoding.EncodeToString(headerBytes) + "." + base64.RawURLEncoding.EncodeToString(claimsBytes)
		h := sha256.Sum256([]byte(input))
		sig, _ := rsa.SignPKCS1v15(rand.Reader, mock.privateKey, crypto.SHA256, h[:])
		idToken := input + "." + base64.RawURLEncoding.EncodeToString(sig)

		resp := oidc.TokenResponse{
			AccessToken: "access_token_xyz",
			IDToken:     idToken,
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	mock.server = httptest.NewServer(mux)
	mock.issuer = mock.server.URL
	return mock
}

func setupSSOHarness(t *testing.T, mock *mockIdPServer) (*auth.Auth, plugins.SSO, organizations.Organization) {
	t.Helper()

	adapter := adaptermem.New()
	cCache := corecache.New()

	orgModule := organizations.New()
	ssoModule := sso.New(
		sso.WithHTTPClient(mock.server.Client()),
		sso.WithSPEntityID("urn:myapp:sp"),
	)

	engine, err := auth.New(auth.Config{
		Adapter: adapter,
		Cache:   cCache,
		Plugins: []auth.PluginModule{orgModule, ssoModule},
	})
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}

	ssoCap, err := auth.Get[plugins.SSO](engine)
	if err != nil {
		t.Fatalf("auth.Get[plugins.SSO]: %v", err)
	}

	orgCap, err := auth.Get[organizations.Organization](engine)
	if err != nil {
		t.Fatalf("auth.Get[organizations.Organization]: %v", err)
	}

	return engine, ssoCap, orgCap
}

func TestSSO_EndToEnd_LifecycleAndOIDC(t *testing.T) {
	ctx := context.Background()
	mock := newMockIdPServer(t, "acme_client_id")
	defer mock.server.Close()

	engine, ssoCap, orgCap := setupSSOHarness(t, mock)

	// 1. Create an enterprise organization
	owner, _ := engine.SignUp(ctx, auth.SignUpInput{Email: "admin@acme.com", Password: "Password123!"})
	orgRecord, err := orgCap.CreateOrganization(ctx, organizations.CreateOrganizationInput{
		Name:    "Acme Corp",
		Slug:    "acme",
		OwnerID: owner.User.ID,
	})
	if err != nil {
		t.Fatalf("CreateOrganization failed: %v", err)
	}

	// 2. Create organization-scoped OIDC SSO configuration
	cfg, err := ssoCap.CreateConfig(ctx, sso.CreateConfigInput{
		OrganizationID: orgRecord.ID,
		Name:           "Acme Okta OIDC",
		Protocol:       sso.ProtocolOIDC,
		Enabled:        true,
		Domains:        []string{"acme.com"},
		JITEnabled:     true,
		DefaultRole:    "member",
		OIDC: &sso.OIDCConfig{
			Issuer:       mock.issuer,
			ClientID:     "acme_client_id",
			ClientSecret: "acme_secret",
			RedirectURI:  "https://myapp.com/sso/callback",
			Scopes:       []string{"openid", "profile", "email"},
		},
	})
	if err != nil {
		t.Fatalf("CreateConfig failed: %v", err)
	}

	// 3. Domain Discovery by email
	discovery, err := ssoCap.DiscoverByEmail(ctx, "alice@acme.com")
	if err != nil {
		t.Fatalf("DiscoverByEmail failed: %v", err)
	}
	if discovery.OrganizationID != orgRecord.ID || discovery.ConfigID != cfg.ID {
		t.Errorf("unexpected discovery: %+v", discovery)
	}

	// 4. Initiate SSO
	initiateRes, err := ssoCap.InitiateSSO(ctx, sso.InitiateSSOInput{
		Email:       "alice@acme.com",
		RedirectURI: "https://myapp.com/sso/callback",
	})
	if err != nil {
		t.Fatalf("InitiateSSO failed: %v", err)
	}
	if initiateRes.State == "" || initiateRes.RedirectURL == "" {
		t.Fatalf("missing state or redirect URL")
	}

	// Retrieve state to get nonce for mock token exchange
	stateSess, _ := ssoCap.GetConfig(ctx, orgRecord.ID, cfg.ID)
	if stateSess == nil {
		t.Fatalf("GetConfig failed")
	}

	// 5. Process SSO Callback (simulate callback with code containing nonce from auth URL)
	parsedURL, _ := url.Parse(initiateRes.RedirectURL)
	nonce := parsedURL.Query().Get("nonce")
	codeWithNonce := "auth_code_xyz:" + nonce

	authRes, err := ssoCap.ProcessSSOCallback(ctx, sso.ProcessSSOCallbackInput{
		State:       initiateRes.State,
		Code:        codeWithNonce,
		RedirectURI: "https://myapp.com/sso/callback",
	})
	if err != nil {
		t.Fatalf("ProcessSSOCallback failed: %v", err)
	}

	if !authRes.IsNewUser {
		t.Errorf("expected JIT provisioned user to be new")
	}
	if authRes.User.Email != "alice@acme.com" {
		t.Errorf("unexpected user email: %s", authRes.User.Email)
	}
	if authRes.Session == nil || authRes.Token == "" {
		t.Errorf("expected session and token to be issued")
	}
}

func TestSSO_EndToEnd_SAML(t *testing.T) {
	ctx := context.Background()
	mock := newMockIdPServer(t, "unused")
	defer mock.server.Close()

	engine, ssoCap, orgCap := setupSSOHarness(t, mock)

	// Create Organization
	owner, _ := engine.SignUp(ctx, auth.SignUpInput{Email: "admin@initech.com", Password: "Password123!"})
	orgRecord, _ := orgCap.CreateOrganization(ctx, organizations.CreateOrganizationInput{
		Name:    "Initech",
		Slug:    "initech",
		OwnerID: owner.User.ID,
	})

	// Create SAML SSO Configuration
	cfg, err := ssoCap.CreateConfig(ctx, sso.CreateConfigInput{
		OrganizationID: orgRecord.ID,
		Name:           "Initech Azure AD",
		Protocol:       sso.ProtocolSAML,
		Enabled:        true,
		Domains:        []string{"initech.com"},
		JITEnabled:     true,
		DefaultRole:    "member",
		SAML: &sso.SAMLConfig{
			EntityID:   "https://sts.windows.net/initech",
			SSOURL:     "https://login.microsoftonline.com/initech/saml2",
			SPEntityID: "urn:myapp:sp",
			SPACSURL:   "https://myapp.com/sso/saml/acs",
		},
	})
	if err != nil {
		t.Fatalf("CreateConfig SAML: %v", err)
	}

	// Initiate SSO
	initRes, err := ssoCap.InitiateSSO(ctx, sso.InitiateSSOInput{
		OrganizationID: orgRecord.ID,
		ConfigID:       cfg.ID,
		RedirectURI:    "https://myapp.com/sso/saml/acs",
	})
	if err != nil {
		t.Fatalf("InitiateSSO SAML: %v", err)
	}

	// Mock valid SAML Response
	now := time.Now().UTC()
	nb := now.Add(-5 * time.Minute).Format(time.RFC3339)
	noa := now.Add(1 * time.Hour).Format(time.RFC3339)
	rawXML := fmt.Sprintf(`<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_saml_resp_1" Version="2.0">
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
    <saml:Assertion ID="_saml_assert_1" Version="2.0">
        <saml:Issuer>https://sts.windows.net/initech</saml:Issuer>
        <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">milton@initech.com</saml:NameID>
        </saml:Subject>
        <saml:Conditions NotBefore="%s" NotOnOrAfter="%s">
            <saml:AudienceRestriction>
                <saml:Audience>urn:myapp:sp</saml:Audience>
            </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AttributeStatement>
            <saml:Attribute Name="email">
                <saml:AttributeValue>milton@initech.com</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="name">
                <saml:AttributeValue>Milton Waddams</saml:AttributeValue>
            </saml:Attribute>
        </saml:AttributeStatement>
    </saml:Assertion>
</samlp:Response>`, nb, noa)

	b64Response := base64.StdEncoding.EncodeToString([]byte(rawXML))

	// Process SAML Callback
	authRes, err := ssoCap.ProcessSSOCallback(ctx, sso.ProcessSSOCallbackInput{
		State:        initRes.State,
		SAMLResponse: b64Response,
		RedirectURI:  "https://myapp.com/sso/saml/acs",
	})
	if err != nil {
		t.Fatalf("ProcessSSOCallback SAML failed: %v", err)
	}

	if authRes.User.Email != "milton@initech.com" {
		t.Errorf("unexpected email: %s", authRes.User.Email)
	}
	if !authRes.IsNewUser {
		t.Errorf("expected Milton to be JIT provisioned")
	}
}
