package saml_test

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	ssosaml "github.com/BladiCreator/go-modular-auth/plugins/sso/saml"
)

func TestSAML_BuildAuthnRequest(t *testing.T) {
	spEntityID := "urn:myapp:sp"
	acsURL := "https://myapp.com/sso/saml/acs"
	idpSSOURL := "https://idp.example.com/sso"
	relayState := "state_12345"

	redirectURL, reqID, err := ssosaml.BuildAuthnRequest(spEntityID, acsURL, idpSSOURL, relayState)
	if err != nil {
		t.Fatalf("BuildAuthnRequest failed: %v", err)
	}

	if reqID == "" || !strings.HasPrefix(reqID, "_") {
		t.Errorf("expected requestID with leading underscore, got %s", reqID)
	}
	if !strings.Contains(redirectURL, "SAMLRequest=") {
		t.Errorf("expected SAMLRequest in URL: %s", redirectURL)
	}
	if !strings.Contains(redirectURL, "RelayState=state_12345") {
		t.Errorf("expected RelayState in URL: %s", redirectURL)
	}
}

func TestSAML_ParseAndValidateResponse(t *testing.T) {
	now := time.Now().UTC()
	notBefore := now.Add(-5 * time.Minute).Format(time.RFC3339)
	notOnOrAfter := now.Add(1 * time.Hour).Format(time.RFC3339)
	spAudience := "urn:myapp:sp"

	rawXML := fmt.Sprintf(`<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_resp123" Version="2.0">
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
    <saml:Assertion ID="_assert456" Version="2.0">
        <saml:Issuer>https://idp.example.com</saml:Issuer>
        <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">bob@acme.com</saml:NameID>
        </saml:Subject>
        <saml:Conditions NotBefore="%s" NotOnOrAfter="%s">
            <saml:AudienceRestriction>
                <saml:Audience>%s</saml:Audience>
            </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AttributeStatement>
            <saml:Attribute Name="email">
                <saml:AttributeValue>bob@acme.com</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="name">
                <saml:AttributeValue>Bob Enterprise</saml:AttributeValue>
            </saml:Attribute>
        </saml:AttributeStatement>
    </saml:Assertion>
</samlp:Response>`, notBefore, notOnOrAfter, spAudience)

	b64Response := base64.StdEncoding.EncodeToString([]byte(rawXML))

	cfg := &ssosaml.SAMLConfig{
		EntityID:   "https://idp.example.com",
		SPEntityID: spAudience,
	}

	data, err := ssosaml.ParseAndValidateResponse(b64Response, cfg, spAudience, now)
	if err != nil {
		t.Fatalf("ParseAndValidateResponse failed: %v", err)
	}

	if data.Subject != "bob@acme.com" {
		t.Errorf("unexpected subject: %s", data.Subject)
	}
	if len(data.Attributes["email"]) == 0 || data.Attributes["email"][0] != "bob@acme.com" {
		t.Errorf("unexpected email attribute: %v", data.Attributes)
	}
}
