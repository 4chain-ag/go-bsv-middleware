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

// PaymentRemittance contains payment metadata
type PaymentRemittance struct {
	DerivationPrefix  string `json:"derivationPrefix"`
	DerivationSuffix  string `json:"derivationSuffix"`
	SenderIdentityKey string `json:"senderIdentityKey"`
}

// InternalizeOutput describes an output to process
type InternalizeOutput struct {
	OutputIndex       int                `json:"outputIndex"`
	Protocol          string             `json:"protocol"`
	PaymentRemittance *PaymentRemittance `json:"paymentRemittance,omitempty"`
}

// InternalizeActionArgs contains parameters for internalizing a transaction
type InternalizeActionArgs struct {
	Tx          []byte              `json:"tx"`
	Outputs     []InternalizeOutput `json:"outputs"`
	Description string              `json:"description"`
	Labels      []string            `json:"labels,omitempty"`
}

// InternalizeActionResult represents the result
type InternalizeActionResult struct {
	Accepted bool `json:"accepted"`
}
