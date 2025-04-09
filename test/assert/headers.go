package assert

import (
	"fmt"
	"net/http"
	"testing"

	walletFixtures "github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet/test"
	"github.com/stretchr/testify/require"
)

var (
	initialResponseHeaders = map[string]string{
		"x-bsv-auth-version":      "0.1",
		"x-bsv-auth-message-type": "initialResponse",
		"x-bsv-auth-identity-key": walletFixtures.ServerIdentityKey,
		"x-bsv-auth-your-nonce":   walletFixtures.ClientNonces[0],
	}
)

// InitialResponseHeaders checks if the response headers are correct for the initial response.
func InitialResponseHeaders(t *testing.T, response *http.Response) {
	for key, value := range initialResponseHeaders {
		require.Equal(t, value, response.Header.Get(key))
	}
	fmt.Println(response.Header.Get("x-bsv-auth-signature"))
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
		"x-bsv-auth-identity-key": walletFixtures.ServerIdentityKey,
		"x-bsv-auth-your-nonce":   walletFixtures.ClientNonces[0],
		"x-bsv-auth-nonce":        walletFixtures.DefaultNonces[1+i*2],
	}
}
