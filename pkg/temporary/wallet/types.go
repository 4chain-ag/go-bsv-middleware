package wallet

// Certificate is a placeholder for the certificate data structure
type Certificate struct {
	// Type is the type of certificate
	Type string `json:"type"`
	// Subject is the subject of the certificate
	Subject string `json:"subject"`
	// SerialNumber is the serial number of the certificate
	SerialNumber string `json:"serialNumber"`
	// Certifier is the certifier of the certificate
	Certifier string `json:"certifier"`
	// RevocationOutpoint is the revocation outpoint of the certificate
	RevocationOutpoint string `json:"revocationOutpoint"`
	// Fields is the map representing custom fields of the certificate (payload)
	Fields map[string]any `json:"fields"`
	// Signature is the signature of the certificate
	Signature string `json:"signature"`
}

// GetPublicKeyOptions defines parameters for GetPublicKey
type GetPublicKeyOptions struct {
	// IdentityKey is a flag to return the identity key
	IdentityKey bool `json:"identityKey"`
	// ProtocolID is the protocol ID for the key
	ProtocolID any `json:"protocolID,omitempty"`
	// KeyID is the key ID for the key
	KeyID string `json:"keyID,omitempty"`
	// Counterparty is the counterparty for the key
	Counterparty string `json:"counterparty,omitempty"`
	// Privileged is a flag to return a privileged key
	Privileged bool `json:"privileged,omitempty"`
	// ForSelf is a flag to return a key for self
	ForSelf bool `json:"forSelf,omitempty"`
}

// VerifiableCertificate is a certificate with a keyring for verifier and optional decrypted fields
type VerifiableCertificate struct {
	Certificate
	Keyring         map[string]string  `json:"keyring"`
	DecryptedFields *map[string]string `json:"decryptedFields,omitempty"`
}

// MasterCertificate is a certificate with a master keyring
type MasterCertificate struct {
	Certificate
	MasterKeyring map[string]string `json:"masterKeyring"`
}
