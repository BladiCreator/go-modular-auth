package saml_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	saml "github.com/BladiCreator/go-modular-auth-saml"
)

func TestSAML_Security_AssertionReplayProtection(t *testing.T) {
	ctx := context.Background()
	h := setupTestHarness(t)

	_, err := h.samlCap.RegisterIdP(ctx, saml.RegisterIdPInput{
		ID:               "idp-replay",
		EntityID:         h.entityID,
		SSOURL:           h.entityID + "/sso",
		Certificates:     []string{h.certPEM},
		AllowUnsolicited: true,
		Enabled:          true,
	})
	if err != nil {
		t.Fatalf("RegisterIdP: %v", err)
	}

	assertionID := "_assert_replay_attack_01"
	b64Response := h.createSignedResponse(assertionID, "", "victim@corp.com", "Victim", time.Now().UTC())

	// First presentation: Success
	res1, err := h.samlCap.ProcessACS(ctx, saml.ProcessACSInput{
		SAMLResponse: b64Response,
	})
	if err != nil {
		t.Fatalf("first ProcessACS failed: %v", err)
	}
	if res1.User.Email != "victim@corp.com" {
		t.Errorf("unexpected email: %s", res1.User.Email)
	}

	// Replay attempt: Must fail with ErrAssertionReplayed
	_, err = h.samlCap.ProcessACS(ctx, saml.ProcessACSInput{
		SAMLResponse: b64Response,
	})
	if err == nil {
		t.Fatalf("expected error on replaying assertion, got nil")
	}
	if !errors.Is(err, saml.ErrAssertionReplayed) {
		t.Errorf("expected ErrAssertionReplayed, got: %v", err)
	}
}

func TestSAML_Security_RequestStateDoubleConsumption(t *testing.T) {
	ctx := context.Background()
	h := setupTestHarness(t)

	_, err := h.samlCap.RegisterIdP(ctx, saml.RegisterIdPInput{
		ID:           "idp-state-consume",
		EntityID:     h.entityID,
		SSOURL:       h.entityID + "/sso",
		Certificates: []string{h.certPEM},
		Enabled:      true,
	})
	if err != nil {
		t.Fatalf("RegisterIdP: %v", err)
	}

	initRes, err := h.samlCap.InitiateAuth(ctx, saml.InitiateAuthInput{
		ProviderID: "idp-state-consume",
	})
	if err != nil {
		t.Fatalf("InitiateAuth: %v", err)
	}

	// First presentation
	resp1 := h.createSignedResponse("_assert_state_1", initRes.RequestID, "user1@corp.com", "User One", time.Now().UTC())
	_, err = h.samlCap.ProcessACS(ctx, saml.ProcessACSInput{
		SAMLResponse: resp1,
		RelayState:   initRes.RelayState,
	})
	if err != nil {
		t.Fatalf("first ProcessACS: %v", err)
	}

	// Second presentation with same RelayState but new assertion ID: must fail with ErrStateConsumed
	resp2 := h.createSignedResponse("_assert_state_2", initRes.RequestID, "user2@corp.com", "User Two", time.Now().UTC())
	_, err = h.samlCap.ProcessACS(ctx, saml.ProcessACSInput{
		SAMLResponse: resp2,
		RelayState:   initRes.RelayState,
	})
	if err == nil {
		t.Fatalf("expected ErrStateConsumed, got nil")
	}
	if !errors.Is(err, saml.ErrStateConsumed) && !errors.Is(err, saml.ErrUnsolicitedNotAllowed) {
		t.Errorf("expected ErrStateConsumed or ErrUnsolicitedNotAllowed, got: %v", err)
	}
}

func TestSAML_Security_TamperedSignature(t *testing.T) {
	ctx := context.Background()
	h := setupTestHarness(t)

	_, err := h.samlCap.RegisterIdP(ctx, saml.RegisterIdPInput{
		ID:               "idp-tamper",
		EntityID:         h.entityID,
		SSOURL:           h.entityID + "/sso",
		Certificates:     []string{h.certPEM},
		AllowUnsolicited: true,
		Enabled:          true,
	})
	if err != nil {
		t.Fatalf("RegisterIdP: %v", err)
	}

	b64Response := h.createSignedResponse("_assert_tamper", "", "alice@corp.com", "Alice", time.Now().UTC())
	rawXML, _ := base64.StdEncoding.DecodeString(b64Response)

	// Tamper with the user email
	tamperedXML := string(rawXML)
	tamperedXML = replaceFirst(tamperedXML, "alice@corp.com", "attacker@corp.com")
	b64Tampered := base64.StdEncoding.EncodeToString([]byte(tamperedXML))

	_, err = h.samlCap.ProcessACS(ctx, saml.ProcessACSInput{
		SAMLResponse: b64Tampered,
	})
	if err == nil {
		t.Fatalf("expected error on tampered assertion, got nil")
	}
	if !errors.Is(err, saml.ErrSignatureInvalid) {
		t.Errorf("expected ErrSignatureInvalid, got: %v", err)
	}
}

func TestSAML_Security_IssuerMismatch(t *testing.T) {
	ctx := context.Background()
	h := setupTestHarness(t)

	_, err := h.samlCap.RegisterIdP(ctx, saml.RegisterIdPInput{
		ID:               "idp-issuer-check",
		EntityID:         "https://legit-idp.com",
		SSOURL:           "https://legit-idp.com/sso",
		Certificates:     []string{h.certPEM},
		AllowUnsolicited: true,
		Enabled:          true,
	})
	if err != nil {
		t.Fatalf("RegisterIdP: %v", err)
	}

	// Response issued by rogue entity ID
	now := time.Now().UTC()
	nb := now.Add(-5 * time.Minute).Format(time.RFC3339)
	noa := now.Add(1 * time.Hour).Format(time.RFC3339)

	signedInfo := `<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#_assert_rogue"><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>placeholder</DigestValue></Reference></SignedInfo>`
	siDigest := sha256.Sum256([]byte(signedInfo))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, h.privKey, crypto.SHA256, siDigest[:])
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	rogueXML := fmt.Sprintf(`<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_resp_rogue" Version="2.0" Destination="%s">
    <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
    <saml:Assertion ID="_assert_rogue" Version="2.0">
        <saml:Issuer>https://rogue-attacker.com</saml:Issuer>
        <saml:Subject><saml:NameID>user@legit.com</saml:NameID></saml:Subject>
        <saml:Conditions NotBefore="%s" NotOnOrAfter="%s">
            <saml:AudienceRestriction><saml:Audience>%s</saml:Audience></saml:AudienceRestriction>
        </saml:Conditions>
        <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
            %s
            <SignatureValue>%s</SignatureValue>
        </Signature>
    </saml:Assertion>
</samlp:Response>`, h.spACSURL, nb, noa, h.spEntityID, signedInfo, sigB64)

	_, err = h.samlCap.ProcessACS(ctx, saml.ProcessACSInput{
		SAMLResponse: base64.StdEncoding.EncodeToString([]byte(rogueXML)),
	})
	if err == nil {
		t.Fatalf("expected error on rogue issuer, got nil")
	}
	if !errors.Is(err, saml.ErrIssuerMismatch) && !errors.Is(err, saml.ErrProviderNotFound) {
		t.Errorf("expected ErrIssuerMismatch or ErrProviderNotFound, got: %v", err)
	}
}

func TestSAML_Security_AudienceMismatch(t *testing.T) {
	ctx := context.Background()
	h := setupTestHarness(t)

	_, err := h.samlCap.RegisterIdP(ctx, saml.RegisterIdPInput{
		ID:               "idp-aud",
		EntityID:         h.entityID,
		SSOURL:           h.entityID + "/sso",
		Certificates:     []string{h.certPEM},
		AllowUnsolicited: true,
		Enabled:          true,
	})
	if err != nil {
		t.Fatalf("RegisterIdP: %v", err)
	}

	now := time.Now().UTC()
	nb := now.Add(-5 * time.Minute).Format(time.RFC3339)
	noa := now.Add(1 * time.Hour).Format(time.RFC3339)

	signedInfo := `<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#_assert_wrong_aud"><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>placeholder</DigestValue></Reference></SignedInfo>`
	siDigest := sha256.Sum256([]byte(signedInfo))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, h.privKey, crypto.SHA256, siDigest[:])
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	wrongAudXML := fmt.Sprintf(`<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_resp_aud" Version="2.0" Destination="%s">
    <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
    <saml:Assertion ID="_assert_wrong_aud" Version="2.0">
        <saml:Issuer>%s</saml:Issuer>
        <saml:Subject><saml:NameID>user@corp.com</saml:NameID></saml:Subject>
        <saml:Conditions NotBefore="%s" NotOnOrAfter="%s">
            <saml:AudienceRestriction><saml:Audience>urn:unrelated:other-service</saml:Audience></saml:AudienceRestriction>
        </saml:Conditions>
        <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
            %s
            <SignatureValue>%s</SignatureValue>
        </Signature>
    </saml:Assertion>
</samlp:Response>`, h.spACSURL, h.entityID, nb, noa, signedInfo, sigB64)

	_, err = h.samlCap.ProcessACS(ctx, saml.ProcessACSInput{
		SAMLResponse: base64.StdEncoding.EncodeToString([]byte(wrongAudXML)),
	})
	if err == nil {
		t.Fatalf("expected error on audience mismatch, got nil")
	}
	if !errors.Is(err, saml.ErrAudienceMismatch) {
		t.Errorf("expected ErrAudienceMismatch, got: %v", err)
	}
}

func TestSAML_Security_ExpiredAssertion(t *testing.T) {
	ctx := context.Background()
	h := setupTestHarness(t)

	_, err := h.samlCap.RegisterIdP(ctx, saml.RegisterIdPInput{
		ID:               "idp-exp",
		EntityID:         h.entityID,
		SSOURL:           h.entityID + "/sso",
		Certificates:     []string{h.certPEM},
		AllowUnsolicited: true,
		Enabled:          true,
	})
	if err != nil {
		t.Fatalf("RegisterIdP: %v", err)
	}

	// Assertion whose NotOnOrAfter was 1 hour ago
	expiredNow := time.Now().UTC().Add(-2 * time.Hour)
	b64Response := h.createSignedResponse("_assert_expired", "", "late@corp.com", "Late", expiredNow)

	_, err = h.samlCap.ProcessACS(ctx, saml.ProcessACSInput{
		SAMLResponse: b64Response,
	})
	if err == nil {
		t.Fatalf("expected error on expired assertion, got nil")
	}
	if !errors.Is(err, saml.ErrAssertionExpired) {
		t.Errorf("expected ErrAssertionExpired, got: %v", err)
	}
}

func TestSAML_Security_UnsolicitedLoginForbidden(t *testing.T) {
	ctx := context.Background()
	h := setupTestHarness(t)

	// IdP with AllowUnsolicited = false (default)
	_, err := h.samlCap.RegisterIdP(ctx, saml.RegisterIdPInput{
		ID:               "idp-no-unsolicited",
		EntityID:         h.entityID,
		SSOURL:           h.entityID + "/sso",
		Certificates:     []string{h.certPEM},
		AllowUnsolicited: false,
		Enabled:          true,
	})
	if err != nil {
		t.Fatalf("RegisterIdP: %v", err)
	}

	b64Response := h.createSignedResponse("_assert_unsolicited_blocked", "", "user@corp.com", "User", time.Now().UTC())

	_, err = h.samlCap.ProcessACS(ctx, saml.ProcessACSInput{
		SAMLResponse: b64Response,
		RelayState:   "", // No request session
	})
	if err == nil {
		t.Fatalf("expected error on unsolicited login when disallowed, got nil")
	}
	if !errors.Is(err, saml.ErrUnsolicitedNotAllowed) {
		t.Errorf("expected ErrUnsolicitedNotAllowed, got: %v", err)
	}
}

func TestSAML_Security_Concurrency(t *testing.T) {
	ctx := context.Background()
	h := setupTestHarness(t)

	_, err := h.samlCap.RegisterIdP(ctx, saml.RegisterIdPInput{
		ID:               "idp-concurrent",
		EntityID:         h.entityID,
		SSOURL:           h.entityID + "/sso",
		Certificates:     []string{h.certPEM},
		AllowUnsolicited: true,
		Enabled:          true,
	})
	if err != nil {
		t.Fatalf("RegisterIdP: %v", err)
	}

	// 20 concurrent goroutines presenting distinct assertions
	const workers = 20
	var wg sync.WaitGroup
	errCh := make(chan error, workers)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			assertionID := fmt.Sprintf("_assert_concurrent_%d", idx)
			email := fmt.Sprintf("worker%d@corp.com", idx)
			b64 := h.createSignedResponse(assertionID, "", email, fmt.Sprintf("Worker %d", idx), time.Now().UTC())

			_, err := h.samlCap.ProcessACS(ctx, saml.ProcessACSInput{
				SAMLResponse: b64,
			})
			if err != nil {
				errCh <- fmt.Errorf("worker %d failed: %w", idx, err)
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrency error: %v", err)
	}
}

func replaceFirst(s, old, new string) string {
	idx := len(s)
	for i := 0; i+len(old) <= len(s); i++ {
		if s[i:i+len(old)] == old {
			idx = i
			break
		}
	}
	if idx == len(s) {
		return s
	}
	return s[:idx] + new + s[idx+len(old):]
}
