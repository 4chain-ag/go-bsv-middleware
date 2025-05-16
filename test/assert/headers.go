package assert

import (
	"net/http"
	"testing"

	"github.com/bsv-blockchain/go-bsv-middleware/test/mocks"
	"github.com/stretchr/testify/require"
)

var (
	initialResponseHeaders = map[string]string{
		"x-bsv-auth-version":      "0.1",
		"x-bsv-auth-message-type": "initialResponse",
		"x-bsv-auth-identity-key": mocks.ServerIdentityKey,
		"x-bsv-auth-your-nonce":   mocks.ClientNonces[0],
	}
)

// InitialResponseHeaders checks if the response headers are correct for the initial response.
func InitialResponseHeaders(t *testing.T, response *http.Response) {
	// Check that required headers are present
	require.NotEmpty(t, response.Header.Get("x-bsv-auth-version"), "x-bsv-auth-version header is empty")
	require.NotEmpty(t, response.Header.Get("x-bsv-auth-message-type"), "x-bsv-auth-message-type header is empty")
	require.NotEmpty(t, response.Header.Get("x-bsv-auth-identity-key"), "x-bsv-auth-identity-key header is empty")
	// TODO: go-sdk is not creating signature
	// require.NotEmpty(t, response.Header.Get("x-bsv-auth-signature"), "x-bsv-auth-signature header is empty")

	// Check specific values where appropriate
	require.Equal(t, "0.1", response.Header.Get("x-bsv-auth-version"), "x-bsv-auth-version header does not match expected value")
	require.Equal(t, "initialResponse", response.Header.Get("x-bsv-auth-message-type"), "x-bsv-auth-message-type header does not match expected value")
}

// GeneralResponseHeaders checks if the response headers are correct for the general response.
func GeneralResponseHeaders(t *testing.T, response *http.Response, requestNumber int) {
	require.NotEmpty(t, response.Header.Get("x-bsv-auth-version"), "x-bsv-auth-version header is empty")
	require.NotEmpty(t, response.Header.Get("x-bsv-auth-identity-key"), "x-bsv-auth-identity-key header is empty")
	require.NotEmpty(t, response.Header.Get("x-bsv-auth-nonce"), "x-bsv-auth-nonce header is empty")
	require.NotEmpty(t, response.Header.Get("x-bsv-auth-your-nonce"), "x-bsv-auth-your-nonce header is empty")
	require.NotEmpty(t, response.Header.Get("x-bsv-auth-request-id"), "request-id header is empty")
	require.NotEmpty(t, response.Header.Get("x-bsv-auth-signature"), "signature header is empty")

	require.Equal(t, "0.1", response.Header.Get("x-bsv-auth-version"), "x-bsv-auth-version header does not match expected value")
	require.Equal(t, "general", response.Header.Get("x-bsv-auth-message-type"), "x-bsv-auth-message-type header does not match expected value")
}
