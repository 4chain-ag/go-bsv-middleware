package mocks

import (
	"context"
	"errors"
	"net/http"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/interfaces"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/utils"
	"github.com/bsv-blockchain/go-sdk/auth"
)

// Headers is a map of headers
type Headers map[string]string

// RequestBody is a placeholder for transport.AuthMessage
type RequestBody auth.AuthMessage

// WithWrongVersion adds a wrong version to the headers
func WithWrongVersion(h map[string]string) {
	h["x-bsv-auth-version"] = "0.2"
}

// WithWrongSignature adds a wrong signature to the headers
func WithWrongSignature(h map[string]string) {
	h["x-bsv-auth-signature"] = "wrong_signature"
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
func NewRequestBody(msg auth.AuthMessage) *RequestBody {
	rb := RequestBody(msg)
	return &rb
}

// WithWrongVersion adds a wrong version to the request body
func (rb *RequestBody) WithWrongVersion() *RequestBody {
	rb.Version = "0.2"
	return rb
}

// WithoutIdentityKey removes the identity key from the request body
func (rb *RequestBody) WithoutIdentityKey() *RequestBody {
	rb.IdentityKey = nil
	return rb
}

// WithoutInitialNonce removes the initial nonce from the request body
func (rb *RequestBody) WithoutInitialNonce() *RequestBody {
	rb.InitialNonce = ""
	return rb
}

// WithoutIdentityKeyAndNonce removes the identity key and nonce from the request body
func (rb *RequestBody) WithoutIdentityKeyAndNonce() *RequestBody {
	rb.IdentityKey = nil
	rb.InitialNonce = ""
	return rb
}

// WithInvalidNonceFormat sets an invalid nonce format in the request body
func (rb *RequestBody) WithInvalidNonceFormat() *RequestBody {
	rb.InitialNonce = "this-is-not-valid-base64!"
	return rb
}

// AuthMessage returns the request body as an AuthMessage
func (rb *RequestBody) AuthMessage() *auth.AuthMessage {
	return (*auth.AuthMessage)(rb)
}

// PrepareInitialRequestBody prepares the initial request body
func PrepareInitialRequestBody(ctx context.Context, mockedWallet interfaces.Wallet) *RequestBody {
	initialRequest := utils.PrepareInitialRequestBody(ctx, mockedWallet)

	return NewRequestBody(initialRequest)
}

// PrepareGeneralRequestHeaders prepares the general request headers
func PrepareGeneralRequestHeaders(
	ctx context.Context,
	mockedWallet interfaces.Wallet,
	previousResponse *auth.AuthMessage,
	request *http.Request,
	opts ...func(m map[string]string)) error {
	if previousResponse == nil {
		return errors.New("previous response is nil")
	}

	if previousResponse.IdentityKey == nil {
		return errors.New("previous response missing identity key")
	}

	yourNonce := previousResponse.InitialNonce
	if yourNonce == "" && previousResponse.Nonce != "" {
		yourNonce = previousResponse.Nonce
	}

	if yourNonce == "" {
		return errors.New("previous response has no nonce to use")
	}

	normalizedResponse := &auth.AuthMessage{
		Version:      previousResponse.Version,
		MessageType:  previousResponse.MessageType,
		IdentityKey:  previousResponse.IdentityKey,
		InitialNonce: yourNonce,
	}

	headers, err := utils.PrepareGeneralRequestHeaders(ctx, mockedWallet, normalizedResponse, utils.RequestData{Request: request})
	if err != nil {
		return errors.New("failed to prepare general request headers: " + err.Error())
	}

	for _, opt := range opts {
		opt(headers)
	}

	for key, value := range headers {
		request.Header.Set(key, value)
	}

	return nil
}
