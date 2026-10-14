// Package saml implements SAML 2.0 Service Provider functionality for enterprise SSO.
package saml

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // SAML 1.1/2.0 compatibility
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// SAMLConfig contains SAML 2.0 specific parameters.
type SAMLConfig struct {
	EntityID     string   `json:"entity_id"`
	SSOURL       string   `json:"sso_url"`
	SLOURL       string   `json:"slo_url,omitempty"`
	Certificates []string `json:"certificates"`
	NameIDFormat string   `json:"name_id_format,omitempty"`
	SPEntityID   string   `json:"sp_entity_id,omitempty"`
	SPACSURL     string   `json:"sp_acs_url,omitempty"`
	SignRequest  bool     `json:"sign_request,omitempty"`
	ForceAuthn   bool     `json:"force_authn,omitempty"`
}

var (
	ErrMalformedResponse      = errors.New("sso saml: malformed response XML")
	ErrStatusNotSuccess       = errors.New("sso saml: response status was not success")
	ErrNoAssertion            = errors.New("sso saml: response contains no assertions")
	ErrExpiredAssertion       = errors.New("sso saml: assertion validity window expired")
	ErrAudienceMismatch       = errors.New("sso saml: audience restriction mismatch")
	ErrSignatureInvalid       = errors.New("sso saml: assertion signature verification failed")
	ErrMissingCertificates    = errors.New("sso saml: no trusted certificates configured for provider")
	ErrSubjectNotFound        = errors.New("sso saml: no subject NameID in assertion")
)

// AuthnRequest represents an outgoing SAML 2.0 AuthnRequest message.
type AuthnRequest struct {
	XMLName                     xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol AuthnRequest"`
	ID                          string   `xml:"ID,attr"`
	Version                     string   `xml:"Version,attr"`
	IssueInstant                string   `xml:"IssueInstant,attr"`
	Destination                 string   `xml:"Destination,attr,omitempty"`
	AssertionConsumerServiceURL string   `xml:"AssertionConsumerServiceURL,attr"`
	ProtocolBinding             string   `xml:"ProtocolBinding,attr"`
	Issuer                      string   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	NameIDPolicy                struct {
		Format      string `xml:"Format,attr,omitempty"`
		AllowCreate bool   `xml:"AllowCreate,attr"`
	} `xml:"NameIDPolicy"`
}

// BuildAuthnRequest creates a deflated, base64-encoded SAML AuthnRequest redirect URL.
func BuildAuthnRequest(spEntityID, acsURL, idpSSOURL, relayState string) (redirectURL string, requestID string, err error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	requestID = "_" + hex.EncodeToString(b)
	now := time.Now().UTC().Format(time.RFC3339)

	req := AuthnRequest{
		ID:                          requestID,
		Version:                     "2.0",
		IssueInstant:                now,
		Destination:                 idpSSOURL,
		AssertionConsumerServiceURL: acsURL,
		ProtocolBinding:             "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
		Issuer:                      spEntityID,
	}
	req.NameIDPolicy.AllowCreate = true
	req.NameIDPolicy.Format = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"

	xmlBytes, err := xml.Marshal(req)
	if err != nil {
		return "", "", err
	}

	// Deflate compress (RFC 1951 raw deflate)
	var buf bytes.Buffer
	flateWriter, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		return "", "", err
	}
	if _, err := flateWriter.Write(xmlBytes); err != nil {
		return "", "", err
	}
	_ = flateWriter.Close()

	encoded := base64.StdEncoding.EncodeToString(buf.Bytes())

	q := url.Values{}
	q.Set("SAMLRequest", encoded)
	if relayState != "" {
		q.Set("RelayState", relayState)
	}

	sep := "?"
	if strings.Contains(idpSSOURL, "?") {
		sep = "&"
	}
	return idpSSOURL + sep + q.Encode(), requestID, nil
}

// Response models the incoming SAML 2.0 Response XML.
type Response struct {
	XMLName      xml.Name  `xml:"Response"`
	ID           string    `xml:"ID,attr"`
	Destination  string    `xml:"Destination,attr"`
	InResponseTo string    `xml:"InResponseTo,attr"`
	Status       Status    `xml:"Status"`
	Assertion    Assertion `xml:"Assertion"`
	Signature    Signature `xml:"Signature"`
}

type Status struct {
	StatusCode struct {
		Value string `xml:"Value,attr"`
	} `xml:"StatusCode"`
}

type Assertion struct {
	ID                 string             `xml:"ID,attr"`
	IssueInstant       string             `xml:"IssueInstant,attr"`
	Issuer             string             `xml:"Issuer"`
	Subject            Subject            `xml:"Subject"`
	Conditions         Conditions         `xml:"Conditions"`
	AttributeStatement AttributeStatement `xml:"AttributeStatement"`
	Signature          Signature          `xml:"Signature"`
}

type Subject struct {
	NameID struct {
		Format string `xml:"Format,attr"`
		Value  string `xml:",chardata"`
	} `xml:"NameID"`
}

type Conditions struct {
	NotBefore           string              `xml:"NotBefore,attr"`
	NotOnOrAfter        string              `xml:"NotOnOrAfter,attr"`
	AudienceRestriction AudienceRestriction `xml:"AudienceRestriction"`
}

type AudienceRestriction struct {
	Audience string `xml:"Audience"`
}

type AttributeStatement struct {
	Attributes []Attribute `xml:"Attribute"`
}

type Attribute struct {
	Name       string   `xml:"Name,attr"`
	Values     []string `xml:"AttributeValue"`
}

type Signature struct {
	SignedInfo struct {
		CanonicalizationMethod struct {
			Algorithm string `xml:"Algorithm,attr"`
		} `xml:"CanonicalizationMethod"`
		SignatureMethod struct {
			Algorithm string `xml:"Algorithm,attr"`
		} `xml:"SignatureMethod"`
		Reference struct {
			URI          string `xml:"URI,attr"`
			DigestMethod struct {
				Algorithm string `xml:"Algorithm,attr"`
			} `xml:"DigestMethod"`
			DigestValue string `xml:"DigestValue"`
		} `xml:"Reference"`
	} `xml:"SignedInfo"`
	SignatureValue string `xml:"SignatureValue"`
	KeyInfo        struct {
		X509Data struct {
			X509Certificate string `xml:"X509Certificate"`
		} `xml:"X509Data"`
	} `xml:"KeyInfo"`
}

// AssertionData holds extracted and validated claims from a SAML Response.
type AssertionData struct {
	Subject    string
	Issuer     string
	Attributes map[string][]string
}

// ParseAndValidateResponse parses, verifies and extracts attributes from a base64 SAMLResponse.
func ParseAndValidateResponse(rawBase64 string, cfg *SAMLConfig, expectedAudience string, now time.Time) (*AssertionData, error) {
	xmlData, err := base64.StdEncoding.DecodeString(rawBase64)
	if err != nil {
		return nil, fmt.Errorf("%w: base64 decode: %v", ErrMalformedResponse, err)
	}

	var resp Response
	if err := xml.Unmarshal(xmlData, &resp); err != nil {
		return nil, fmt.Errorf("%w: xml parse: %v", ErrMalformedResponse, err)
	}

	// 1. Verify status
	if !strings.HasSuffix(resp.Status.StatusCode.Value, ":Success") {
		return nil, fmt.Errorf("%w: %s", ErrStatusNotSuccess, resp.Status.StatusCode.Value)
	}

	assertion := resp.Assertion
	if assertion.ID == "" {
		return nil, ErrNoAssertion
	}

	// 2. Validate Subject NameID
	subject := strings.TrimSpace(assertion.Subject.NameID.Value)
	if subject == "" {
		return nil, ErrSubjectNotFound
	}

	// 3. Validate Conditions (NotBefore / NotOnOrAfter) with 2m clock skew
	skew := 2 * time.Minute
	if assertion.Conditions.NotBefore != "" {
		nb, err := time.Parse(time.RFC3339, assertion.Conditions.NotBefore)
		if err == nil && now.Add(skew).Before(nb) {
			return nil, fmt.Errorf("%w: assertion not yet valid", ErrExpiredAssertion)
		}
	}
	if assertion.Conditions.NotOnOrAfter != "" {
		noa, err := time.Parse(time.RFC3339, assertion.Conditions.NotOnOrAfter)
		if err == nil && now.After(noa.Add(skew)) {
			return nil, fmt.Errorf("%w: assertion expired at %v", ErrExpiredAssertion, noa)
		}
	}

	// 4. Validate Audience
	aud := assertion.Conditions.AudienceRestriction.Audience
	if aud != "" && expectedAudience != "" && aud != expectedAudience {
		return nil, fmt.Errorf("%w: expected %s, got %s", ErrAudienceMismatch, expectedAudience, aud)
	}

	// 5. Verify cryptographic signature if certificates configured
	if len(cfg.Certificates) > 0 {
		sig := assertion.Signature
		if sig.SignatureValue == "" {
			sig = resp.Signature
		}
		if sig.SignatureValue == "" {
			return nil, fmt.Errorf("%w: signature element missing", ErrSignatureInvalid)
		}
		if err := verifyXMLSignature(sig, cfg.Certificates, xmlData); err != nil {
			return nil, err
		}
	}

	// 6. Extract attributes
	attrs := make(map[string][]string)
	for _, a := range assertion.AttributeStatement.Attributes {
		name := strings.TrimSpace(a.Name)
		if name != "" {
			attrs[name] = a.Values
		}
	}

	return &AssertionData{
		Subject:    subject,
		Issuer:     assertion.Issuer,
		Attributes: attrs,
	}, nil
}

func verifyXMLSignature(sig Signature, certPEMs []string, fullXML []byte) error {
	sigVal, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(sig.SignatureValue, "\n", ""))
	if err != nil {
		return fmt.Errorf("%w: decode signature value: %v", ErrSignatureInvalid, err)
	}

	var pubKeys []*rsa.PublicKey
	for _, p := range certPEMs {
		block, _ := pem.Decode([]byte(p))
		var certBytes []byte
		if block != nil {
			certBytes = block.Bytes
		} else {
			// Try raw base64 cert
			certBytes, _ = base64.StdEncoding.DecodeString(strings.TrimSpace(p))
		}
		if len(certBytes) > 0 {
			cert, err := x509.ParseCertificate(certBytes)
			if err == nil {
				if rsaPub, ok := cert.PublicKey.(*rsa.PublicKey); ok {
					pubKeys = append(pubKeys, rsaPub)
				}
			}
		}
	}

	if len(pubKeys) == 0 {
		return ErrMissingCertificates
	}

	// Determine digest and signature algorithms
	sigAlg := sig.SignedInfo.SignatureMethod.Algorithm
	var h crypto.Hash
	var digest []byte

	// Calculate signature digest over XML content
	if strings.Contains(sigAlg, "rsa-sha1") {
		h = crypto.SHA1
		d := sha1.Sum(fullXML) //nolint:gosec
		digest = d[:]
	} else {
		h = crypto.SHA256
		d := sha256.Sum256(fullXML)
		digest = d[:]
	}

	// Verify against any matching trusted public key
	var lastErr error
	for _, key := range pubKeys {
		if err := rsa.VerifyPKCS1v15(key, h, digest, sigVal); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}

	return fmt.Errorf("%w: %v", ErrSignatureInvalid, lastErr)
}
