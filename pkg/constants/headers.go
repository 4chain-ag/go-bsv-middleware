package constants

// BRC-104 HTTP header constants
// These headers are used for BSV authentication over HTTP transport
const (
	// AuthHeaderPrefix is the common prefix for all BSV auth headers
	AuthHeaderPrefix = "x-bsv-auth-"

	// HeaderVersion specifies the version of the auth protocol
	HeaderVersion = AuthHeaderPrefix + "version"

	// HeaderMessageType specifies the type of auth message
	HeaderMessageType = AuthHeaderPrefix + "message-type"

	// HeaderIdentityKey contains the sender's identity public key
	HeaderIdentityKey = AuthHeaderPrefix + "identity-key"

	// HeaderNonce contains the sender's nonce
	HeaderNonce = AuthHeaderPrefix + "nonce"

	// HeaderYourNonce contains the recipient's nonce (echoed back)
	HeaderYourNonce = AuthHeaderPrefix + "your-nonce"

	// HeaderSignature contains the message signature
	HeaderSignature = AuthHeaderPrefix + "signature"

	// HeaderRequestID contains the request ID for correlation
	HeaderRequestID = AuthHeaderPrefix + "request-id"

	// HeaderRequestedCertificates contains requested certificates (if used)
	HeaderRequestedCertificates = AuthHeaderPrefix + "requested-certificates"
)
