package metadata

import (
	"encoding/xml"
	"fmt"
)

// IdPMetadata represents SAML 2.0 EntityDescriptor for Identity Provider.
type IdPMetadata struct {
	XMLName  xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata md:EntityDescriptor"`
	EntityID string   `xml:"entityID,attr"`
	IDPDesc  IDPSSODescriptor
}

type IDPSSODescriptor struct {
	XMLName                 xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata md:IDPSSODescriptor"`
	WantAuthnRequestsSigned bool     `xml:"WantAuthnRequestsSigned,attr"`
	ProtocolSupport         string   `xml:"protocolSupportEnumeration,attr"`
	KeyDescriptor           *KeyDescriptor
	SingleSignOnServices    []Endpoint `xml:"md:SingleSignOnService"`
}

type KeyDescriptor struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata md:KeyDescriptor"`
	Use     string   `xml:"use,attr"`
	KeyInfo KeyInfo
}

type KeyInfo struct {
	XMLName  xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# ds:KeyInfo"`
	X509Data X509Data
}

type X509Data struct {
	XMLName         xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# ds:X509Data"`
	X509Certificate string   `xml:"ds:X509Certificate"`
}

type Endpoint struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
}

// GenerateIdPMetadata produces IdP EntityDescriptor XML bytes.
func GenerateIdPMetadata(entityID, ssoURL, certBase64 string) ([]byte, error) {
	meta := IdPMetadata{
		EntityID: entityID,
		IDPDesc: IDPSSODescriptor{
			WantAuthnRequestsSigned: false,
			ProtocolSupport:         "urn:oasis:names:tc:SAML:2.0:protocol",
			KeyDescriptor: &KeyDescriptor{
				Use: "signing",
				KeyInfo: KeyInfo{
					X509Data: X509Data{
						X509Certificate: certBase64,
					},
				},
			},
			SingleSignOnServices: []Endpoint{
				{
					Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
					Location: ssoURL,
				},
				{
					Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
					Location: ssoURL,
				},
			},
		},
	}

	raw, err := xml.MarshalIndent(meta, "", "  ")
	if err != nil {
		return nil, err
	}
	return []byte(fmt.Sprintf("%s\n%s", xml.Header, string(raw))), nil
}
