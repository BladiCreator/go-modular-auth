package saml

import (
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
)

// GenerateSPMetadata produces standard SAML 2.0 Service Provider EntityDescriptor XML.
func GenerateSPMetadata(entityID, acsURL, sloURL string, certPEM string) ([]byte, error) {
	if entityID == "" || acsURL == "" {
		return nil, errors.New("saml: entityID and acsURL are required for metadata generation")
	}

	cleanCert := ""
	if certPEM != "" {
		cleanCert = stripPEMHeaders(certPEM)
	}

	var keyDescriptorXML string
	if cleanCert != "" {
		keyDescriptorXML = fmt.Sprintf(`
    <md:KeyDescriptor use="signing">
        <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:X509Data>
                <ds:X509Certificate>%s</ds:X509Certificate>
            </ds:X509Data>
        </ds:KeyInfo>
    </md:KeyDescriptor>`, cleanCert)
	}

	var sloXML string
	if sloURL != "" {
		sloXML = fmt.Sprintf(`
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="%s"/>`, sloURL)
	}

	metadataXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">
  <md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">%s%s
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="%s" index="1" isDefault="true"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>`, entityID, keyDescriptorXML, sloXML, acsURL)

	return []byte(metadataXML), nil
}

type idpMetadataXML struct {
	XMLName          xml.Name `xml:"EntityDescriptor"`
	EntityID         string   `xml:"entityID,attr"`
	IDPSSODescriptor struct {
		KeyDescriptors []struct {
			Use     string `xml:"use,attr"`
			KeyInfo struct {
				X509Data struct {
					X509Certificate string `xml:"X509Certificate"`
				} `xml:"X509Data"`
			} `xml:"KeyInfo"`
		} `xml:"KeyDescriptor"`
		SingleSignOnServices []struct {
			Binding  string `xml:"Binding,attr"`
			Location string `xml:"Location,attr"`
		} `xml:"SingleSignOnService"`
		SingleLogoutServices []struct {
			Binding  string `xml:"Binding,attr"`
			Location string `xml:"Location,attr"`
		} `xml:"SingleLogoutService"`
	} `xml:"IDPSSODescriptor"`
}

// ParsedIdPMetadata holds extracted parameters from IdP metadata XML.
type ParsedIdPMetadata struct {
	EntityID     string
	SSOURL       string
	SLOURL       string
	Certificates []string
}

// ParseIdPMetadata parses SAML 2.0 Identity Provider EntityDescriptor XML.
func ParseIdPMetadata(xmlData []byte) (*ParsedIdPMetadata, error) {
	var doc idpMetadataXML
	if err := xml.Unmarshal(xmlData, &doc); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMetadataParseFailed, err)
	}

	if doc.EntityID == "" {
		return nil, fmt.Errorf("%w: missing entityID attribute", ErrMetadataParseFailed)
	}

	res := &ParsedIdPMetadata{EntityID: doc.EntityID}

	for _, sso := range doc.IDPSSODescriptor.SingleSignOnServices {
		if strings.Contains(sso.Binding, "HTTP-Redirect") || strings.Contains(sso.Binding, "HTTP-POST") {
			if res.SSOURL == "" {
				res.SSOURL = sso.Location
			}
		}
	}
	for _, slo := range doc.IDPSSODescriptor.SingleLogoutServices {
		if res.SLOURL == "" {
			res.SLOURL = slo.Location
		}
	}
	for _, kd := range doc.IDPSSODescriptor.KeyDescriptors {
		certStr := strings.TrimSpace(kd.KeyInfo.X509Data.X509Certificate)
		if certStr != "" {
			certStr = strings.ReplaceAll(certStr, "\r", "")
			certStr = strings.ReplaceAll(certStr, "\n", "")
			res.Certificates = append(res.Certificates, certStr)
		}
	}

	if res.SSOURL == "" {
		return nil, fmt.Errorf("%w: no SingleSignOnService location found", ErrMetadataParseFailed)
	}

	return res, nil
}

func stripPEMHeaders(pemStr string) string {
	lines := strings.Split(pemStr, "\n")
	var b strings.Builder
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "-----") {
			continue
		}
		b.WriteString(trimmed)
	}
	// Verify base64
	cleaned := b.String()
	if _, err := base64.StdEncoding.DecodeString(cleaned); err == nil {
		return cleaned
	}
	return pemStr
}
