package samlprovider

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/BladiCreator/go-modular-auth/user"
)

func generateID(prefix string) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}

// BuildSAMLResponseXML creates a valid SAML 2.0 Response XML document containing an authentication assertion.
func BuildSAMLResponseXML(idpEntityID string, sp *ServiceProvider, u *user.User, inResponseTo string, now time.Time, key *rsa.PrivateKey, certBase64 string) (string, error) {
	responseID := generateID("resp")
	assertionID := generateID("asrt")
	issueInstant := now.UTC().Format(time.RFC3339)
	notBefore := now.UTC().Add(-1 * time.Minute).Format(time.RFC3339)
	notOnOrAfter := now.UTC().Add(10 * time.Minute).Format(time.RFC3339)

	inResponseToAttr := ""
	if inResponseTo != "" {
		inResponseToAttr = fmt.Sprintf(` InResponseTo="%s"`, inResponseTo)
	}

	assertionXML := fmt.Sprintf(`<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" IssueInstant="%s" Version="2.0">`+
		`<saml:Issuer>%s</saml:Issuer>`+
		`<saml:Subject>`+
		`<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">%s</saml:NameID>`+
		`<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">`+
		`<saml:SubjectConfirmationData%s NotOnOrAfter="%s" Recipient="%s"/>`+
		`</saml:SubjectConfirmation>`+
		`</saml:Subject>`+
		`<saml:Conditions NotBefore="%s" NotOnOrAfter="%s">`+
		`<saml:AudienceRestriction>`+
		`<saml:Audience>%s</saml:Audience>`+
		`</saml:AudienceRestriction>`+
		`</saml:Conditions>`+
		`<saml:AuthnStatement AuthnInstant="%s">`+
		`<saml:AuthnContext>`+
		`<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>`+
		`</saml:AuthnContext>`+
		`</saml:AuthnStatement>`+
		`<saml:AttributeStatement>`+
		`<saml:Attribute Name="email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">`+
		`<saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">%s</saml:AttributeValue>`+
		`</saml:Attribute>`+
		`</saml:AttributeStatement>`+
		`</saml:Assertion>`,
		assertionID, issueInstant, idpEntityID, u.Email, inResponseToAttr, notOnOrAfter, sp.ACSURL,
		notBefore, notOnOrAfter, sp.EntityID, issueInstant, u.Email)

	// Sign the Assertion
	digest := sha256.Sum256([]byte(assertionXML))
	digestBase64 := base64.StdEncoding.EncodeToString(digest[:])

	signedInfoXML := fmt.Sprintf(`<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">`+
		`<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>`+
		`<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>`+
		`<ds:Reference URI="#%s">`+
		`<ds:Transforms>`+
		`<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>`+
		`<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>`+
		`</ds:Transforms>`+
		`<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>`+
		`<ds:DigestValue>%s</ds:DigestValue>`+
		`</ds:Reference>`+
		`</ds:SignedInfo>`, assertionID, digestBase64)

	siDigest := sha256.Sum256([]byte(signedInfoXML))
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, siDigest[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign assertion: %w", err)
	}
	sigBase64 := base64.StdEncoding.EncodeToString(sigBytes)

	signatureXML := fmt.Sprintf(`<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">`+
		`%s`+
		`<ds:SignatureValue>%s</ds:SignatureValue>`+
		`<ds:KeyInfo>`+
		`<ds:X509Data>`+
		`<ds:X509Certificate>%s</ds:X509Certificate>`+
		`</ds:X509Data>`+
		`</ds:KeyInfo>`+
		`</ds:Signature>`, signedInfoXML, sigBase64, certBase64)

	// Inject Signature right after Issuer in Assertion
	issuerEndTag := fmt.Sprintf("<saml:Issuer>%s</saml:Issuer>", idpEntityID)
	signedAssertionXML := fmt.Sprintf("%s%s%s",
		assertionXML[:len(issuerEndTag)+len(fmt.Sprintf(`<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" IssueInstant="%s" Version="2.0">`, assertionID, issueInstant))],
		signatureXML,
		assertionXML[len(issuerEndTag)+len(fmt.Sprintf(`<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" IssueInstant="%s" Version="2.0">`, assertionID, issueInstant)):],
	)

	fullResponseXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>`+
		`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Destination="%s" ID="%s"%s IssueInstant="%s" Version="2.0">`+
		`<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml:Issuer>`+
		`<samlp:Status>`+
		`<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>`+
		`</samlp:Status>`+
		`%s`+
		`</samlp:Response>`, sp.ACSURL, responseID, inResponseToAttr, issueInstant, idpEntityID, signedAssertionXML)

	return fullResponseXML, nil
}
