package entity

import "time"

// Passkey representa una credencial WebAuthn registrada para un usuario.
type Passkey struct {
	ID           string    `json:"id"`
	Name         *string   `json:"name,omitempty"`       // Nombre amigable o resuelto por AAGUID
	UserID       string    `json:"userId"`               // ID del usuario propietario
	CredentialID string    `json:"credentialID"`         // Identificador único de credencial (Base64URL)
	PublicKey    string    `json:"publicKey"`            // Clave pública COSE / PKIX (Base64)
	Counter      uint32    `json:"counter"`              // Contador de firmas para mitigación de repetición/clonado
	DeviceType   string    `json:"deviceType"`           // "singleDevice" o "multiDevice" (sincronizada)
	BackedUp     bool      `json:"backedUp"`             // Indica si la clave tiene respaldo en la nube (iCloud, Google, etc.)
	Transports   *string   `json:"transports,omitempty"` // Transportes soportados ("usb,ble,nfc,internal,hybrid")
	AAGUID       *string   `json:"aaguid,omitempty"`     // GUID del modelo de autenticador
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}
