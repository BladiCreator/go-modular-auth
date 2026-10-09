package saml

import (
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
	"time"
)

type samlResponseXML struct {
	XMLName      xml.Name         `xml:"Response"`
	ID           string           `xml:"ID,attr"`
	Destination  string           `xml:"Destination,attr"`
	InResponseTo string           `xml:"InResponseTo,attr"`
	Status       samlStatusXML    `xml:"Status"`
	Assertion    samlAssertionXML `xml:"Assertion"`
	Signature    samlSignatureXML `xml:"Signature"`
}

type samlStatusXML struct {
	StatusCode struct {
		Value string `xml:"Value,attr"`
	} `xml:"StatusCode"`
	StatusMessage string `xml:"StatusMessage"`
}

type samlAssertionXML struct {
	ID                  string                  `xml:"ID,attr"`
	IssueInstant        string                  `xml:"IssueInstant,attr"`
	Issuer              string                  `xml:"Issuer"`
	Subject             samlSubjectXML          `xml:"Subject"`
	Conditions          samlConditionsXML       `xml:"Conditions"`
	AuthnStatement      samlAuthnStatementXML   `xml:"AuthnStatement"`
	AttributeStatement  samlAttributeStatement  `xml:"AttributeStatement"`
	Signature           samlSignatureXML        `xml:"Signature"`
}

type samlSubjectXML struct {
	NameID struct {
		Format string `xml:"Format,attr"`
		Value  string `xml:",chardata"`
	} `xml:"NameID"`
	SubjectConfirmation struct {
		Method                  string `xml:"Method,attr"`
		SubjectConfirmationData struct {
			InResponseTo string `xml:"InResponseTo,attr"`
			NotOnOrAfter string `xml:"NotOnOrAfter,attr"`
			Recipient    string `xml:"Recipient,attr"`
		} `xml:"SubjectConfirmationData"`
	} `xml:"SubjectConfirmation"`
}

type samlConditionsXML struct {
	NotBefore           string `xml:"NotBefore,attr"`
	NotOnOrAfter        string `xml:"NotOnOrAfter,attr"`
	AudienceRestriction struct {
		Audience string `xml:"Audience"`
	} `xml:"AudienceRestriction"`
}

type samlAuthnStatementXML struct {
	SessionIndex string `xml:"SessionIndex,attr"`
}

type samlAttributeStatement struct {
	Attributes []struct {
		Name         string   `xml:"Name,attr"`
		FriendlyName string   `xml:"FriendlyName,attr"`
		Values       []string `xml:"AttributeValue"`
	} `xml:"Attribute"`
}

type samlSignatureXML struct {
	SignedInfo struct {
		CanonicalizationMethod struct {
			Algorithm string `xml:"Algorithm,attr"`
		} `xml:"CanonicalizationMethod"`
		SignatureMethod struct {
			Algorithm string `xml:"Algorithm,attr"`
		} `xml:"SignatureMethod"`
		Reference struct {
			DigestMethod struct {
				Algorithm string `xml:"Algorithm,attr"`
			} `xml:"DigestMethod"`
			DigestValue string `xml:"DigestValue"`
		} `xml:"Reference"`
	} `xml:"SignedInfo"`
	SignatureValue string `xml:"SignatureValue"`
}

// ParsedAssertionResult holds validated assertion details and expiry timestamp.
type ParsedAssertionResult struct {
	Assertion    *SAMLAssertion
	InResponseTo string
	ExpiresAt    time.Time
}

// ParseAndVerifyResponse parses, verifies signatures, conditions, and extracts claims from a SAMLResponse string.
func ParseAndVerifyResponse(rawBase64 string, cfg *IdPConfig, expectedSPEntityID, expectedACSURL string, now time.Time) (*ParsedAssertionResult, error) {
	xmlBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rawBase64))
	if err != nil {
		return nil, fmt.Errorf("%w: base64 decode: %v", ErrInvalidInput, err)
	}

	var resp samlResponseXML
	if err := xml.Unmarshal(xmlBytes, &resp); err != nil {
		return nil, fmt.Errorf("%w: xml decode: %v", ErrInvalidInput, err)
	}

	// 1. Validate Status
	if !strings.HasSuffix(resp.Status.StatusCode.Value, ":Success") {
		return nil, fmt.Errorf("%w: %s (%s)", ErrStatusNotSuccess, resp.Status.StatusCode.Value, resp.Status.StatusMessage)
	}

	assertion := resp.Assertion
	if assertion.ID == "" {
		return nil, errors.New("saml: response contains no valid assertions")
	}

	// 2. Validate Issuer
	if cfg.EntityID != "" {
		assertionIssuer := strings.TrimSpace(assertion.Issuer)
		if assertionIssuer != "" && assertionIssuer != cfg.EntityID {
			return nil, fmt.Errorf("%w: expected %s, got %s", ErrIssuerMismatch, cfg.EntityID, assertionIssuer)
		}
	}

	// 3. Validate Destination
	if resp.Destination != "" && expectedACSURL != "" {
		if !strings.EqualFold(strings.TrimRight(resp.Destination, "/"), strings.TrimRight(expectedACSURL, "/")) {
			return nil, fmt.Errorf("%w: expected %s, got %s", ErrDestinationMismatch, expectedACSURL, resp.Destination)
		}
	}

	// 4. Validate Audience
	expectedAud := cfg.SPEntityID
	if expectedAud == "" {
		expectedAud = expectedSPEntityID
	}
	aud := strings.TrimSpace(assertion.Conditions.AudienceRestriction.Audience)
	if aud != "" && expectedAud != "" && aud != expectedAud {
		return nil, fmt.Errorf("%w: expected %s, got %s", ErrAudienceMismatch, expectedAud, aud)
	}

	// 5. Validate Conditions (NotBefore, NotOnOrAfter) with Clock Skew
	skew := cfg.ClockSkew
	if skew == 0 {
		skew = 2 * time.Minute
	}

	var expiryTime time.Time
	if assertion.Conditions.NotBefore != "" {
		nb, err := time.Parse(time.RFC3339, assertion.Conditions.NotBefore)
		if err == nil && now.Add(skew).Before(nb) {
			return nil, fmt.Errorf("%w: assertion not valid before %v", ErrAssertionNotYetValid, nb)
		}
	}
	if assertion.Conditions.NotOnOrAfter != "" {
		noa, err := time.Parse(time.RFC3339, assertion.Conditions.NotOnOrAfter)
		if err == nil {
			expiryTime = noa
			if now.After(noa.Add(skew)) {
				return nil, fmt.Errorf("%w: assertion expired at %v", ErrAssertionExpired, noa)
			}
		}
	}
	if expiryTime.IsZero() {
		expiryTime = now.Add(10 * time.Minute)
	}

	// 6. Verify Digital Signature
	if len(cfg.Certificates) > 0 {
		sigXML := assertion.Signature
		if sigXML.SignatureValue == "" {
			sigXML = resp.Signature
		}
		if sigXML.SignatureValue == "" {
			return nil, fmt.Errorf("%w: assertion or response signature required", ErrSignatureInvalid)
		}

		sig := XMLSignature{
			SignatureValue:  sigXML.SignatureValue,
			SignatureMethod: sigXML.SignedInfo.SignatureMethod.Algorithm,
			DigestValue:     sigXML.SignedInfo.Reference.DigestValue,
			DigestMethod:    sigXML.SignedInfo.Reference.DigestMethod.Algorithm,
		}

		if err := VerifySignature(sig, cfg.Certificates, xmlBytes); err != nil {
			return nil, err
		}
	}

	// 7. Extract Subject NameID
	subject := strings.TrimSpace(assertion.Subject.NameID.Value)
	if subject == "" {
		return nil, ErrMissingSubject
	}

	// 8. Extract Attributes
	attributes := make(map[string][]string)
	for _, a := range assertion.AttributeStatement.Attributes {
		name := strings.TrimSpace(a.Name)
		if name != "" {
			attributes[name] = a.Values
		}
		friendly := strings.TrimSpace(a.FriendlyName)
		if friendly != "" && friendly != name {
			attributes[friendly] = a.Values
		}
	}

	inRespTo := resp.InResponseTo
	if inRespTo == "" {
		inRespTo = assertion.Subject.SubjectConfirmation.SubjectConfirmationData.InResponseTo
	}

	return &ParsedAssertionResult{
		Assertion: &SAMLAssertion{
			ID:           assertion.ID,
			Issuer:       assertion.Issuer,
			Subject:      subject,
			Format:       assertion.Subject.NameID.Format,
			SessionIndex: assertion.AuthnStatement.SessionIndex,
			Attributes:   attributes,
		},
		InResponseTo: inRespTo,
		ExpiresAt:    expiryTime,
	}, nil
}

// ExtractIssuer peeks at the Issuer in the incoming SAMLResponse without full verification.
func ExtractIssuer(rawBase64 string) string {
	xmlBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rawBase64))
	if err != nil {
		return ""
	}
	var resp samlResponseXML
	if err := xml.Unmarshal(xmlBytes, &resp); err != nil {
		return ""
	}
	if resp.Assertion.Issuer != "" {
		return strings.TrimSpace(resp.Assertion.Issuer)
	}
	return ""
}

// ExtractInResponseTo peeks at the InResponseTo attribute in the incoming SAMLResponse.
func ExtractInResponseTo(rawBase64 string) string {
	xmlBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rawBase64))
	if err != nil {
		return ""
	}
	var resp samlResponseXML
	if err := xml.Unmarshal(xmlBytes, &resp); err != nil {
		return ""
	}
	if resp.InResponseTo != "" {
		return strings.TrimSpace(resp.InResponseTo)
	}
	return strings.TrimSpace(resp.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.InResponseTo)
}
