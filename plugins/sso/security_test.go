package sso_test

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	organizations "github.com/BladiCreator/go-modular-auth/plugins/organizations"
	sso "github.com/BladiCreator/go-modular-auth/plugins/sso"
)

func TestSSO_Security_CrossTenantViolation(t *testing.T) {
	ctx := context.Background()
	mock := newMockIdPServer(t, "unused")
	defer mock.server.Close()

	engine, ssoCap, orgCap := setupSSOHarness(t, mock)

	// Create Organization with allowed domain "acme.com"
	owner, _ := engine.SignUp(ctx, auth.SignUpInput{Email: "owner@acme.com", Password: "Password123!"})
	orgRecord, _ := orgCap.CreateOrganization(ctx, organizations.CreateOrganizationInput{
		Name:    "Acme Corp",
		Slug:    "acme",
		OwnerID: owner.User.ID,
	})

	cfg, _ := ssoCap.CreateConfig(ctx, sso.CreateConfigInput{
		OrganizationID: orgRecord.ID,
		Name:           "Acme SAML",
		Protocol:       sso.ProtocolSAML,
		Enabled:        true,
		Domains:        []string{"acme.com"}, // ONLY acme.com!
		JITEnabled:     true,
		SAML: &sso.SAMLConfig{
			EntityID:   "https://idp.acme.com",
			SSOURL:     "https://idp.acme.com/sso",
			SPEntityID: "urn:myapp:sp",
		},
	})

	initRes, _ := ssoCap.InitiateSSO(ctx, sso.InitiateSSOInput{
		OrganizationID: orgRecord.ID,
		ConfigID:       cfg.ID,
		RedirectURI:    "https://myapp.com/cb",
	})

	// Malicious/confused IdP sends assertion for "@competitor.com"
	now := time.Now().UTC()
	rawXML := fmt.Sprintf(`<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_resp_evil" Version="2.0">
    <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
    <saml:Assertion ID="_assert_evil" Version="2.0">
        <saml:Issuer>https://idp.acme.com</saml:Issuer>
        <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">infiltrator@competitor.com</saml:NameID>
        </saml:Subject>
        <saml:Conditions NotBefore="%s" NotOnOrAfter="%s">
            <saml:AudienceRestriction><saml:Audience>urn:myapp:sp</saml:Audience></saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AttributeStatement>
            <saml:Attribute Name="email"><saml:AttributeValue>infiltrator@competitor.com</saml:AttributeValue></saml:Attribute>
        </saml:AttributeStatement>
    </saml:Assertion>
</samlp:Response>`, now.Add(-time.Minute).Format(time.RFC3339), now.Add(time.Hour).Format(time.RFC3339))

	b64 := base64.StdEncoding.EncodeToString([]byte(rawXML))

	_, err := ssoCap.ProcessSSOCallback(ctx, sso.ProcessSSOCallbackInput{
		State:        initRes.State,
		SAMLResponse: b64,
		RedirectURI:  "https://myapp.com/cb",
	})
	if !errors.Is(err, sso.ErrCrossTenantViolation) {
		t.Fatalf("expected ErrCrossTenantViolation for unauthorized domain, got: %v", err)
	}
}

func TestSSO_Security_DomainConflict(t *testing.T) {
	ctx := context.Background()
	mock := newMockIdPServer(t, "unused")
	defer mock.server.Close()

	engine, ssoCap, orgCap := setupSSOHarness(t, mock)

	// Org 1 claims acme.com
	u1, _ := engine.SignUp(ctx, auth.SignUpInput{Email: "u1@test.com", Password: "Password123!"})
	org1, _ := orgCap.CreateOrganization(ctx, organizations.CreateOrganizationInput{Name: "Org 1", Slug: "org1", OwnerID: u1.User.ID})

	_, err := ssoCap.CreateConfig(ctx, sso.CreateConfigInput{
		OrganizationID: org1.ID,
		Name:           "SSO 1",
		Protocol:       sso.ProtocolSAML,
		Enabled:        true,
		Domains:        []string{"shared-domain.com"},
		SAML:           &sso.SAMLConfig{EntityID: "https://idp1.com", SSOURL: "https://idp1.com/sso"},
	})
	if err != nil {
		t.Fatalf("CreateConfig 1 failed: %v", err)
	}

	// Org 2 attempts to claim shared-domain.com
	u2, _ := engine.SignUp(ctx, auth.SignUpInput{Email: "u2@test.com", Password: "Password123!"})
	org2, _ := orgCap.CreateOrganization(ctx, organizations.CreateOrganizationInput{Name: "Org 2", Slug: "org2", OwnerID: u2.User.ID})

	_, err = ssoCap.CreateConfig(ctx, sso.CreateConfigInput{
		OrganizationID: org2.ID,
		Name:           "SSO 2",
		Protocol:       sso.ProtocolSAML,
		Enabled:        true,
		Domains:        []string{"shared-domain.com"},
		SAML:           &sso.SAMLConfig{EntityID: "https://idp2.com", SSOURL: "https://idp2.com/sso"},
	})
	if !errors.Is(err, sso.ErrDomainConflict) {
		t.Fatalf("expected ErrDomainConflict, got: %v", err)
	}
}

func TestSSO_Security_ReplayPrevention(t *testing.T) {
	ctx := context.Background()
	mock := newMockIdPServer(t, "unused")
	defer mock.server.Close()

	engine, ssoCap, orgCap := setupSSOHarness(t, mock)

	u, _ := engine.SignUp(ctx, auth.SignUpInput{Email: "owner@replay.com", Password: "Password123!"})
	org, _ := orgCap.CreateOrganization(ctx, organizations.CreateOrganizationInput{Name: "Replay Org", Slug: "replay", OwnerID: u.User.ID})

	cfg, _ := ssoCap.CreateConfig(ctx, sso.CreateConfigInput{
		OrganizationID: org.ID,
		Name:           "SAML Replay",
		Protocol:       sso.ProtocolSAML,
		Enabled:        true,
		Domains:        []string{"replay.com"},
		JITEnabled:     true,
		SAML:           &sso.SAMLConfig{EntityID: "https://idp.com", SSOURL: "https://idp.com/sso", SPEntityID: "urn:myapp:sp"},
	})

	initRes, _ := ssoCap.InitiateSSO(ctx, sso.InitiateSSOInput{
		OrganizationID: org.ID,
		ConfigID:       cfg.ID,
		RedirectURI:    "https://myapp.com/cb",
	})

	now := time.Now().UTC()
	rawXML := fmt.Sprintf(`<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_resp_replay" Version="2.0">
    <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
    <saml:Assertion ID="_assert_replay" Version="2.0">
        <saml:Issuer>https://idp.com</saml:Issuer>
        <saml:Subject><saml:NameID>user@replay.com</saml:NameID></saml:Subject>
        <saml:Conditions NotBefore="%s" NotOnOrAfter="%s">
            <saml:AudienceRestriction><saml:Audience>urn:myapp:sp</saml:Audience></saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AttributeStatement>
            <saml:Attribute Name="email"><saml:AttributeValue>user@replay.com</saml:AttributeValue></saml:Attribute>
        </saml:AttributeStatement>
    </saml:Assertion>
</samlp:Response>`, now.Add(-time.Minute).Format(time.RFC3339), now.Add(time.Hour).Format(time.RFC3339))

	b64 := base64.StdEncoding.EncodeToString([]byte(rawXML))

	// First consumption succeeds
	_, err := ssoCap.ProcessSSOCallback(ctx, sso.ProcessSSOCallbackInput{
		State:        initRes.State,
		SAMLResponse: b64,
		RedirectURI:  "https://myapp.com/cb",
	})
	if err != nil {
		t.Fatalf("first callback failed: %v", err)
	}

	// Replay attempt MUST fail with ErrStateConsumed
	_, err = ssoCap.ProcessSSOCallback(ctx, sso.ProcessSSOCallbackInput{
		State:        initRes.State,
		SAMLResponse: b64,
		RedirectURI:  "https://myapp.com/cb",
	})
	if !errors.Is(err, sso.ErrStateConsumed) {
		t.Fatalf("expected ErrStateConsumed on replay, got: %v", err)
	}
}

func TestSSO_Security_JITDisabled(t *testing.T) {
	ctx := context.Background()
	mock := newMockIdPServer(t, "unused")
	defer mock.server.Close()

	engine, ssoCap, orgCap := setupSSOHarness(t, mock)

	u, _ := engine.SignUp(ctx, auth.SignUpInput{Email: "owner@nojit.com", Password: "Password123!"})
	org, _ := orgCap.CreateOrganization(ctx, organizations.CreateOrganizationInput{Name: "NoJIT Org", Slug: "nojit", OwnerID: u.User.ID})

	cfg, _ := ssoCap.CreateConfig(ctx, sso.CreateConfigInput{
		OrganizationID: org.ID,
		Name:           "SAML NoJIT",
		Protocol:       sso.ProtocolSAML,
		Enabled:        true,
		Domains:        []string{"nojit.com"},
		JITEnabled:     false, // JIT DISABLED!
		SAML:           &sso.SAMLConfig{EntityID: "https://idp.com", SSOURL: "https://idp.com/sso", SPEntityID: "urn:myapp:sp"},
	})

	initRes, _ := ssoCap.InitiateSSO(ctx, sso.InitiateSSOInput{
		OrganizationID: org.ID,
		ConfigID:       cfg.ID,
		RedirectURI:    "https://myapp.com/cb",
	})

	now := time.Now().UTC()
	rawXML := fmt.Sprintf(`<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_resp_nojit" Version="2.0">
    <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
    <saml:Assertion ID="_assert_nojit" Version="2.0">
        <saml:Issuer>https://idp.com</saml:Issuer>
        <saml:Subject><saml:NameID>unknown@nojit.com</saml:NameID></saml:Subject>
        <saml:Conditions NotBefore="%s" NotOnOrAfter="%s">
            <saml:AudienceRestriction><saml:Audience>urn:myapp:sp</saml:Audience></saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AttributeStatement>
            <saml:Attribute Name="email"><saml:AttributeValue>unknown@nojit.com</saml:AttributeValue></saml:Attribute>
        </saml:AttributeStatement>
    </saml:Assertion>
</samlp:Response>`, now.Add(-time.Minute).Format(time.RFC3339), now.Add(time.Hour).Format(time.RFC3339))

	b64 := base64.StdEncoding.EncodeToString([]byte(rawXML))

	_, err := ssoCap.ProcessSSOCallback(ctx, sso.ProcessSSOCallbackInput{
		State:        initRes.State,
		SAMLResponse: b64,
		RedirectURI:  "https://myapp.com/cb",
	})
	if !errors.Is(err, sso.ErrJITDisabled) {
		t.Fatalf("expected ErrJITDisabled, got: %v", err)
	}
}

func TestSSO_Security_AccountConflict(t *testing.T) {
	ctx := context.Background()
	mock := newMockIdPServer(t, "unused")
	defer mock.server.Close()

	engine, ssoCap, orgCap := setupSSOHarness(t, mock)

	// User already exists in Core with password
	existing, _ := engine.SignUp(ctx, auth.SignUpInput{Email: "existing@autolink.com", Password: "Password123!"})
	org, _ := orgCap.CreateOrganization(ctx, organizations.CreateOrganizationInput{Name: "AutoLink Org", Slug: "autolink", OwnerID: existing.User.ID})

	cfg, _ := ssoCap.CreateConfig(ctx, sso.CreateConfigInput{
		OrganizationID: org.ID,
		Name:           "SAML NoAutoLink",
		Protocol:       sso.ProtocolSAML,
		Enabled:        true,
		Domains:        []string{"autolink.com"},
		JITEnabled:     true,
		AutoLink:       false, // Auto-linking disabled!
		SAML:           &sso.SAMLConfig{EntityID: "https://idp.com", SSOURL: "https://idp.com/sso", SPEntityID: "urn:myapp:sp"},
	})

	initRes, _ := ssoCap.InitiateSSO(ctx, sso.InitiateSSOInput{
		OrganizationID: org.ID,
		ConfigID:       cfg.ID,
		RedirectURI:    "https://myapp.com/cb",
	})

	now := time.Now().UTC()
	rawXML := fmt.Sprintf(`<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_resp_collision" Version="2.0">
    <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
    <saml:Assertion ID="_assert_collision" Version="2.0">
        <saml:Issuer>https://idp.com</saml:Issuer>
        <saml:Subject><saml:NameID>existing@autolink.com</saml:NameID></saml:Subject>
        <saml:Conditions NotBefore="%s" NotOnOrAfter="%s">
            <saml:AudienceRestriction><saml:Audience>urn:myapp:sp</saml:Audience></saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AttributeStatement>
            <saml:Attribute Name="email"><saml:AttributeValue>existing@autolink.com</saml:AttributeValue></saml:Attribute>
        </saml:AttributeStatement>
    </saml:Assertion>
</samlp:Response>`, now.Add(-time.Minute).Format(time.RFC3339), now.Add(time.Hour).Format(time.RFC3339))

	b64 := base64.StdEncoding.EncodeToString([]byte(rawXML))

	_, err := ssoCap.ProcessSSOCallback(ctx, sso.ProcessSSOCallbackInput{
		State:        initRes.State,
		SAMLResponse: b64,
		RedirectURI:  "https://myapp.com/cb",
	})
	if !errors.Is(err, sso.ErrAccountConflict) {
		t.Fatalf("expected ErrAccountConflict, got: %v", err)
	}
}
