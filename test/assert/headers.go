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
	for key, value := range initialResponseHeaders {
		require.Equal(t, value, response.Header.Get(key))
	}
	require.NotNil(t, response.Header.Get("x-bsv-auth-signature"))
}

// GeneralResponseHeaders checks if the response headers are correct for the general response.
func GeneralResponseHeaders(t *testing.T, response *http.Response, requestNumber int) {
	for key, value := range getGeneralResponseHeaders(requestNumber) {
		require.Equal(t, value, response.Header.Get(key))
	}

	require.NotNil(t, response.Header.Get("x-bsv-auth-request-id"))
	require.NotNil(t, response.Header.Get("x-bsv-auth-signature"))
}

func getGeneralResponseHeaders(i int) map[string]string {
	return map[string]string{
		"x-bsv-auth-version":      "0.1",
		"x-bsv-auth-message-type": "general",
		"x-bsv-auth-identity-key": mocks.ServerIdentityKey,
		"x-bsv-auth-your-nonce":   mocks.ClientNonces[0],
		"x-bsv-auth-nonce":        mocks.DefaultNonces[1+i*2],
	}
}
