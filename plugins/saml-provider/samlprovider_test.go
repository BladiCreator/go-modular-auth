package samlprovider_test

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	auth "github.com/BladiCreator/go-modular-auth"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapter/memory"
	samlprovider "github.com/BladiCreator/go-modular-auth/plugins/saml-provider"
	"github.com/BladiCreator/go-modular-auth/user"
)

func TestSAMLProvider_Lifecycle(t *testing.T) {
	ctx := context.Background()
	mod := samlprovider.New(
		samlprovider.WithEntityID("https://idp.example.com/metadata"),
		samlprovider.WithSSOURL("https://idp.example.com/sso"),
	)

	a, err := auth.New(auth.Config{
		Adapter: adaptermem.New(),
		Plugins: []auth.PluginModule{mod},
	})
	if err != nil {
		t.Fatalf("failed to create auth engine: %v", err)
	}

	provider, err := auth.Get[samlprovider.SAMLProvider](a)
	if err != nil {
		t.Fatalf("failed to get SAMLProvider: %v", err)
	}

	// 1. Metadata check
	metaXML, err := provider.GetMetadata()
	if err != nil {
		t.Fatalf("failed to generate metadata: %v", err)
	}
	if !strings.Contains(string(metaXML), "https://idp.example.com/metadata") {
		t.Errorf("expected entityID in metadata, got: %s", string(metaXML))
	}
	if !strings.Contains(string(metaXML), "IDPSSODescriptor") {
		t.Errorf("expected IDPSSODescriptor in metadata")
	}

	// 2. Register SP
	sp := &samlprovider.ServiceProvider{
		EntityID: "https://sp.example.com/saml",
		ACSURL:   "https://sp.example.com/saml/acs",
	}
	if err := provider.RegisterSP(sp); err != nil {
		t.Fatalf("failed to register SP: %v", err)
	}

	// 3. Build Response
	testUser := &user.User{
		ID:            "u-456",
		Email:         "bob@example.com",
		EmailVerified: true,
	}

	b64Response, err := provider.BuildResponse(ctx, sp.EntityID, testUser, "req-789")
	if err != nil {
		t.Fatalf("failed to build SAML response: %v", err)
	}

	xmlBytes, err := base64.StdEncoding.DecodeString(b64Response)
	if err != nil {
		t.Fatalf("failed to base64 decode SAML response: %v", err)
	}
	xmlStr := string(xmlBytes)

	if !strings.Contains(xmlStr, "bob@example.com") {
		t.Errorf("expected user email in assertion")
	}
	if !strings.Contains(xmlStr, "SignatureValue") {
		t.Errorf("expected XML Signature in assertion")
	}
	if !strings.Contains(xmlStr, "req-789") {
		t.Errorf("expected inResponseTo reference in response")
	}
}
