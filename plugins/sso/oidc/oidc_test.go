package oidc_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	ssooidc "github.com/BladiCreator/go-modular-auth/plugins/sso/oidc"
)

func TestOIDCClient_DiscoveryAndBuildURL(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		doc := ssooidc.DiscoveryDocument{
			Issuer:                "https://idp.example.com",
			AuthorizationEndpoint: "https://idp.example.com/oauth/authorize",
			TokenEndpoint:         "https://idp.example.com/oauth/token",
			JWKSUri:               "https://idp.example.com/.well-known/jwks.json",
		}
		_ = json.NewEncoder(w).Encode(doc)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := ssooidc.NewClient(srv.Client())
	ctx := context.Background()

	doc, err := client.Discover(ctx, srv.URL, "")
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}
	if doc.AuthorizationEndpoint != "https://idp.example.com/oauth/authorize" {
		t.Errorf("unexpected auth endpoint: %s", doc.AuthorizationEndpoint)
	}

	cfg := &ssooidc.OIDCConfig{
		ClientID:    "client_123",
		RedirectURI: "https://app.com/cb",
		Scopes:      []string{"openid", "email"},
	}

	verifier, challenge, err := ssooidc.GeneratePKCE()
	if err != nil || verifier == "" || challenge == "" {
		t.Fatalf("GeneratePKCE failed")
	}

	nonce := ssooidc.GenerateNonce()
	authURL := client.BuildAuthURL(doc.AuthorizationEndpoint, cfg, "state_xyz", nonce, challenge)

	if !strings.Contains(authURL, "client_id=client_123") {
		t.Errorf("missing client_id in URL: %s", authURL)
	}
	if !strings.Contains(authURL, "code_challenge="+challenge) {
		t.Errorf("missing code_challenge in URL: %s", authURL)
	}
}

func TestOIDCClient_VerifyIDToken(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}

	pub := &privKey.PublicKey
	nStr := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	eBytes := big.NewInt(int64(pub.E)).Bytes()
	eStr := base64.RawURLEncoding.EncodeToString(eBytes)

	jwks := &ssooidc.JWKS{
		Keys: []ssooidc.JWK{
			{
				Kty: "RSA",
				Kid: "key-1",
				Alg: "RS256",
				N:   nStr,
				E:   eStr,
			},
		},
	}

	now := time.Now().UTC()
	issuer := "https://idp.example.com"
	clientID := "client_test"
	nonce := "nonce_test_abc"

	headerJSON, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "key-1"})
	claimsJSON, _ := json.Marshal(map[string]any{
		"iss":   issuer,
		"sub":   "user_oidc_999",
		"aud":   clientID,
		"exp":   now.Add(1 * time.Hour).Unix(),
		"iat":   now.Unix(),
		"nonce": nonce,
		"email": "user@example.com",
		"name":  "User OIDC",
	})

	hB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	cB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := hB64 + "." + cB64

	h := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, h[:])
	if err != nil {
		t.Fatalf("rsa sign failed: %v", err)
	}
	rawToken := signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)

	cfg := &ssooidc.OIDCConfig{
		Issuer:   issuer,
		ClientID: clientID,
	}

	client := ssooidc.NewClient(nil)
	claims, err := client.VerifyIDToken(rawToken, jwks, cfg, nonce, now)
	if err != nil {
		t.Fatalf("VerifyIDToken failed: %v", err)
	}
	if claims.Subject != "user_oidc_999" || claims.Email != "user@example.com" {
		t.Errorf("unexpected claims: %+v", claims)
	}
}
