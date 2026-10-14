package saml_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	saml "github.com/BladiCreator/go-modular-auth/plugins/saml"
	"github.com/BladiCreator/go-modular-auth/plugins/saml/plugins"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapter/memory"
	corecache "github.com/BladiCreator/go-modular-auth/cache/memory"
)

type samlTestHarness struct {
	engine     *auth.Auth
	samlCap    plugins.SAML
	privKey    *rsa.PrivateKey
	certPEM    string
	entityID   string
	spEntityID string
	spACSURL   string
}

func setupTestHarness(t *testing.T) *samlTestHarness {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "saml-idp.example.com",
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))

	spEntityID := "urn:myapp:sp"
	spACSURL := "https://myapp.com/saml/acs"
	entityID := "https://idp.example.com"

	adapter := adaptermem.New()
	cCache := corecache.New()

	samlModule := saml.New(
		saml.WithSPEntityID(spEntityID),
		saml.WithSPACSURL(spACSURL),
	)

	engine, err := auth.New(auth.Config{
		Adapter: adapter,
		Cache:   cCache,
		Plugins: []auth.PluginModule{samlModule},
	})
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}

	samlCap, err := auth.Get[plugins.SAML](engine)
	if err != nil {
		t.Fatalf("auth.Get[plugins.SAML]: %v", err)
	}

	return &samlTestHarness{
		engine:     engine,
		samlCap:    samlCap,
		privKey:    privKey,
		certPEM:    certPEM,
		entityID:   entityID,
		spEntityID: spEntityID,
		spACSURL:   spACSURL,
	}
}

func (h *samlTestHarness) createSignedResponse(assertionID, inResponseTo, email, name string, now time.Time) string {
	nb := now.Add(-5 * time.Minute).Format(time.RFC3339)
	noa := now.Add(1 * time.Hour).Format(time.RFC3339)

	rawAssertion := fmt.Sprintf(`<saml:Assertion ID="%s" Version="2.0">
        <saml:Issuer>%s</saml:Issuer>
        <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">%s</saml:NameID>
        </saml:Subject>
        <saml:Conditions NotBefore="%s" NotOnOrAfter="%s">
            <saml:AudienceRestriction>
                <saml:Audience>%s</saml:Audience>
            </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AttributeStatement>
            <saml:Attribute Name="email">
                <saml:AttributeValue>%s</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="name">
                <saml:AttributeValue>%s</saml:AttributeValue>
            </saml:Attribute>
        </saml:AttributeStatement>
    </saml:Assertion>`, assertionID, h.entityID, email, nb, noa, h.spEntityID, email, name)

	aDigest := sha256.Sum256([]byte(rawAssertion))
	digestB64 := base64.StdEncoding.EncodeToString(aDigest[:])

	signedInfo := fmt.Sprintf(`<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#%s"><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>%s</DigestValue></Reference></SignedInfo>`, assertionID, digestB64)

	siDigest := sha256.Sum256([]byte(signedInfo))
	sig, err := rsa.SignPKCS1v15(rand.Reader, h.privKey, crypto.SHA256, siDigest[:])
	if err != nil {
		panic(err)
	}
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	sigElement := fmt.Sprintf(`<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">%s<SignatureValue>%s</SignatureValue></Signature>`, signedInfo, sigB64)
	assertionWithSig := strings.Replace(rawAssertion, "</saml:Assertion>", sigElement+"</saml:Assertion>", 1)

	signedXML := fmt.Sprintf(`<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_resp_123" Version="2.0"
                Destination="%s" InResponseTo="%s">
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
    %s
</samlp:Response>`, h.spACSURL, inResponseTo, assertionWithSig)

	return base64.StdEncoding.EncodeToString([]byte(signedXML))
}

func TestSAML_SPMetadata(t *testing.T) {
	ctx := context.Background()
	h := setupTestHarness(t)

	metaBytes, err := h.samlCap.GetSPMetadata(ctx)
	if err != nil {
		t.Fatalf("GetSPMetadata failed: %v", err)
	}

	metadata := string(metaBytes)
	if !strings.Contains(metadata, `entityID="urn:myapp:sp"`) {
		t.Errorf("missing entityID in metadata: %s", metadata)
	}
	if !strings.Contains(metadata, `Location="https://myapp.com/saml/acs"`) {
		t.Errorf("missing ACS location in metadata: %s", metadata)
	}
}

func TestSAML_RegisterFromMetadata(t *testing.T) {
	ctx := context.Background()
	h := setupTestHarness(t)

	idpXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://okta.corp.com">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://okta.corp.com/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>`)

	cfg, err := h.samlCap.RegisterIdPFromMetadata(ctx, "okta-meta", "org-1", []byte(idpXML))
	if err != nil {
		t.Fatalf("RegisterIdPFromMetadata failed: %v", err)
	}

	if cfg.EntityID != "https://okta.corp.com" || cfg.SSOURL != "https://okta.corp.com/sso" {
		t.Errorf("unexpected registered config: %+v", cfg)
	}
}

func TestSAML_EndToEnd_SPInitiatedAuth(t *testing.T) {
	ctx := context.Background()
	h := setupTestHarness(t)

	// 1. Register IdP
	_, err := h.samlCap.RegisterIdP(ctx, saml.RegisterIdPInput{
		ID:           "test-idp",
		EntityID:     h.entityID,
		SSOURL:       h.entityID + "/sso",
		Certificates: []string{h.certPEM},
		Enabled:      true,
	})
	if err != nil {
		t.Fatalf("RegisterIdP failed: %v", err)
	}

	// 2. InitiateAuth
	initRes, err := h.samlCap.InitiateAuth(ctx, saml.InitiateAuthInput{
		ProviderID:  "test-idp",
		RedirectURI: "https://myapp.com/dashboard",
	})
	if err != nil {
		t.Fatalf("InitiateAuth failed: %v", err)
	}

	if initRes.RedirectURL == "" || initRes.RelayState == "" {
		t.Fatalf("missing redirect URL or relay state")
	}

	// 3. ProcessACS with signed response
	assertionID := "_assert_test_101"
	b64Response := h.createSignedResponse(assertionID, initRes.RequestID, "alice@enterprise.com", "Alice Smith", time.Now().UTC())

	authRes, err := h.samlCap.ProcessACS(ctx, saml.ProcessACSInput{
		SAMLResponse: b64Response,
		RelayState:   initRes.RelayState,
	})
	if err != nil {
		t.Fatalf("ProcessACS failed: %v", err)
	}

	if !authRes.IsNewUser {
		t.Errorf("expected new user JIT provisioned")
	}
	if authRes.User.Email != "alice@enterprise.com" {
		t.Errorf("unexpected email: %s", authRes.User.Email)
	}
	if authRes.Session == nil || authRes.Token == "" {
		t.Errorf("expected session and token issued")
	}
	if authRes.RedirectURI != "https://myapp.com/dashboard" {
		t.Errorf("expected redirectURI to be preserved: %s", authRes.RedirectURI)
	}

	// 4. ListLinkedAccounts & UnlinkAccount
	accounts, err := h.samlCap.ListLinkedAccounts(ctx, authRes.User.ID)
	if err != nil || len(accounts) != 1 {
		t.Fatalf("ListLinkedAccounts failed: len=%d, err=%v", len(accounts), err)
	}

	if err := h.samlCap.UnlinkAccount(ctx, authRes.User.ID, "test-idp"); err != nil {
		t.Fatalf("UnlinkAccount failed: %v", err)
	}

	accountsAfter, _ := h.samlCap.ListLinkedAccounts(ctx, authRes.User.ID)
	if len(accountsAfter) != 0 {
		t.Errorf("expected 0 linked accounts after unlinking")
	}
}

func TestSAML_UnsolicitedLogin(t *testing.T) {
	ctx := context.Background()
	h := setupTestHarness(t)

	// Register IdP with AllowUnsolicited = true
	_, err := h.samlCap.RegisterIdP(ctx, saml.RegisterIdPInput{
		ID:               "idp-unsolicited",
		EntityID:         h.entityID,
		SSOURL:           h.entityID + "/sso",
		Certificates:     []string{h.certPEM},
		AllowUnsolicited: true,
		Enabled:          true,
	})
	if err != nil {
		t.Fatalf("RegisterIdP: %v", err)
	}

	assertionID := "_assert_idp_init_55"
	b64Response := h.createSignedResponse(assertionID, "", "bob@enterprise.com", "Bob Unsolicited", time.Now().UTC())

	authRes, err := h.samlCap.ProcessACS(ctx, saml.ProcessACSInput{
		SAMLResponse: b64Response,
		RelayState:   "", // Empty relay state for IdP-initiated login
	})
	if err != nil {
		t.Fatalf("ProcessACS unsolicited failed: %v", err)
	}

	if authRes.User.Email != "bob@enterprise.com" {
		t.Errorf("unexpected email: %s", authRes.User.Email)
	}
}
