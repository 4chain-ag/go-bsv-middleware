package mocks

import (
	"encoding/hex"
	"errors"
	"net/http"

	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
	"github.com/4chain-ag/go-bsv-middleware/pkg/transport"
	"github.com/4chain-ag/go-bsv-middleware/pkg/utils"
)

// Headers is a map of headers
type Headers map[string]string

// RequestBody is a placeholder for transport.AuthMessage
type RequestBody transport.AuthMessage

// WithWrongVersion adds a wrong version to the headers
func WithWrongVersion(h map[string]string) {
	h["x-bsv-auth-version"] = "0.2"
}

// WithWrongSignature adds a wrong signature to the headers
func WithWrongSignature(h map[string]string) {
	h["x-bsv-auth-signature"] = "wrong_signature"
}

// WithWrongSignatureInHex adds a wrong signature in hex to the headers
func WithWrongSignatureInHex(h map[string]string) {
	h["x-bsv-auth-signature"] = hex.EncodeToString([]byte("wrong_signature"))
}

// WithWrongYourNonce adds a wrong your nonce to the headers
func WithWrongYourNonce(h map[string]string) {
	h["x-bsv-auth-your-nonce"] = "wrong_your_nonce"
}

// WithWrongNonce adds a wrong nonce to the headers
func WithWrongNonce(h map[string]string) {
	h["x-bsv-auth-nonce"] = "wrong_nonce"
}

// NewRequestBody creates a new RequestBody from an AuthMessage
func NewRequestBody(msg transport.AuthMessage) *RequestBody {
	rb := RequestBody(msg)
	return &rb
}

// WithWrongVersion adds a wrong version to the request body
func (rb *RequestBody) WithWrongVersion() *RequestBody {
	rb.Version = "0.2"
	return rb
}

// WithoutIdentityKeyAndNonce removes the identity key and nonce from the request body
func (rb *RequestBody) WithoutIdentityKeyAndNonce() *RequestBody {
	rb.IdentityKey = ""
	rb.InitialNonce = ""
	return rb
}

// AuthMessage returns the request body as an AuthMessage
func (rb *RequestBody) AuthMessage() *transport.AuthMessage {
	return (*transport.AuthMessage)(rb)
}

// PrepareInitialRequestBody prepares the initial request body
func PrepareInitialRequestBody(mockedWallet wallet.WalletInterface) *RequestBody {
	initialRequest := utils.PrepareInitialRequestBody(mockedWallet)

	return NewRequestBody(initialRequest)
}

// PrepareGeneralRequestHeaders prepares the general request headers
func PrepareGeneralRequestHeaders(mockedWallet wallet.WalletInterface, previousResponse *transport.AuthMessage, request *http.Request, opts ...func(m map[string]string)) error {
	headers, err := utils.PrepareGeneralRequestHeaders(mockedWallet, previousResponse, request)
	if err != nil {
		return errors.New("failed to prepare general request headers")
	}

	for _, opt := range opts {
		opt(headers)
	}

	for key, value := range headers {
		request.Header.Set(key, value)
	}

	return nil
}
