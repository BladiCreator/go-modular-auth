package saml

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// AuthnRequestXML represents the SAML 2.0 protocol AuthnRequest message structure.
type AuthnRequestXML struct {
	XMLName                     xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol AuthnRequest"`
	ID                          string   `xml:"ID,attr"`
	Version                     string   `xml:"Version,attr"`
	IssueInstant                string   `xml:"IssueInstant,attr"`
	Destination                 string   `xml:"Destination,attr,omitempty"`
	AssertionConsumerServiceURL string   `xml:"AssertionConsumerServiceURL,attr"`
	ProtocolBinding             string   `xml:"ProtocolBinding,attr"`
	ForceAuthn                  bool     `xml:"ForceAuthn,attr,omitempty"`
	Issuer                      string   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	NameIDPolicy                struct {
		Format      string `xml:"Format,attr,omitempty"`
		AllowCreate bool   `xml:"AllowCreate,attr"`
	} `xml:"NameIDPolicy"`
}

// BuildAuthnRequest constructs a SAML AuthnRequest redirect URL for the HTTP-Redirect binding.
func BuildAuthnRequest(spEntityID, acsURL, idpSSOURL, relayState, nameIDFormat string, forceAuthn bool, now time.Time) (redirectURL string, requestID string, err error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	requestID = "_req_" + hex.EncodeToString(b)

	req := AuthnRequestXML{
		ID:                          requestID,
		Version:                     "2.0",
		IssueInstant:                now.Format(time.RFC3339),
		Destination:                 idpSSOURL,
		AssertionConsumerServiceURL: acsURL,
		ProtocolBinding:             "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
		ForceAuthn:                  forceAuthn,
		Issuer:                      spEntityID,
	}
	req.NameIDPolicy.AllowCreate = true
	if nameIDFormat != "" {
		req.NameIDPolicy.Format = nameIDFormat
	} else {
		req.NameIDPolicy.Format = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
	}

	xmlBytes, err := xml.Marshal(req)
	if err != nil {
		return "", "", fmt.Errorf("marshal authn request: %w", err)
	}

	// Deflate compression (RFC 1951 raw deflate)
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		return "", "", fmt.Errorf("deflate writer: %w", err)
	}
	if _, err := w.Write(xmlBytes); err != nil {
		return "", "", err
	}
	if err := w.Close(); err != nil {
		return "", "", err
	}

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
