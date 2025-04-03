package transport

import (
	"net/http"

	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
)

const (
	// AuthVersion is the version of the authentication protocol.
	AuthVersion = "0.1"
	// IdentityKey is the key used to store the identity key in the context.
	IdentityKey = "identityKey"
	// RequestID is the key used to store the request ID in the context.
	RequestID = "requestID"
)

// Definition of the Message Types used in the authentication process.
const (
	// InitialRequest is the first message sent by the client to the server.
	InitialRequest MessageType = "initialRequest"
	// InitialResponse is the response to the initial request.
	InitialResponse MessageType = "initialResponse"
	// CertificateRequest is the message sent by the server to request certificates from the client.
	CertificateRequest MessageType = "certificateRequest"
	// CertificateResponse is the response to the certificate request.
	CertificateResponse MessageType = "certificateResponse"
	// General is a normal endpoint authorized by middleware.
	General MessageType = "general"
)

// MessageType represents the type of message sent between peers during the authentication process.
type MessageType string

// AuthMessage represents a type message sent between peers during the authentication process.
type AuthMessage struct {
	Version               string                        `json:"version"`
	MessageType           MessageType                   `json:"messageType"`
	IdentityKey           string                        `json:"identityKey"`
	Nonce                 *string                       `json:"nonce,omitempty"`
	InitialNonce          string                        `json:"initialNonce"`
	YourNonce             *string                       `json:"yourNonce,omitempty"`
	Payload               *[]byte                       `json:"payload,omitempty"`
	Signature             *[]byte                       `json:"signature,omitempty"`
	Certificate           *wallet.VerifiableCertificate `json:"certificate,omitempty"`
	RequestedCertificates *RequestedCertificateSet      `json:"requestedCertificates"`
}

// RequestedCertificateSet represents the set of certificates requested by a peer.
type RequestedCertificateSet struct {
	Certifiers []string            `json:"certifiers"`
	Types      map[string][]string `json:"types"`
}

// OnCertificatesReceivedFunc callback type for handling received certificates
type OnCertificatesReceivedFunc func(
	senderPublicKey string,
	certs []any,
	req *http.Request,
	res http.ResponseWriter,
	next func(),
)

// MessageCallback is a callback function for handling messages. Placeholder for now.
type MessageCallback func(message AuthMessage) error

// String returns a string from a MessageType.
func (m *MessageType) String() string {
	return string(*m)
}
