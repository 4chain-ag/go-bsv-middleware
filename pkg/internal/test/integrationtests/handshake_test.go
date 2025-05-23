package integrationtests

import (
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/test/mocks"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/test/testutils"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
)

func TestHandshake_HappyPath(t *testing.T) {
	// given
	sessionManager := mocks.NewMockableSessionManager()
	serverWallet := mocks.NewMockableWallet()
	server := mocks.CreateMockHTTPServer(serverWallet, sessionManager, mocks.WithLogger).
		WithHandler("/", mocks.IndexHandler().WithAuthMiddleware())
	defer server.Close()

	clientWallet := mocks.CreateClientMockWallet()
	initialRequest := mocks.PrepareInitialRequestBody(t.Context(), clientWallet)

	serverWallet.OnCreateNonceOnce(mocks.DefaultNonces[0], nil)
	serverWallet.OnCreateSignatureOnce(prepareExampleSignature(t), nil)
	serverWallet.OnGetPublicKeyOnce(prepareExampleIdentityKey(t), nil)
	serverWallet.OnCreateHmacOnce(&wallet.CreateHmacResult{
		Hmac: []byte("mockhmacsignature"),
	}, nil)

	// when
	response, err := server.SendNonGeneralRequest(t, initialRequest.AuthMessage())

	// then
	require.NoError(t, err)
	testutils.ResponseOK(t, response)
}

func TestHandshake_MissingInitialNonce(t *testing.T) {
	// given
	sessionManager := mocks.NewMockableSessionManager()
	serverWallet := mocks.NewMockableWallet()
	server := mocks.CreateMockHTTPServer(serverWallet, sessionManager, mocks.WithLogger).
		WithHandler("/", mocks.IndexHandler().WithAuthMiddleware())
	defer server.Close()

	clientWallet := mocks.CreateClientMockWallet()

	initialRequest := mocks.PrepareInitialRequestBody(t.Context(), clientWallet)
	initialRequest.InitialNonce = ""

	serverWallet.OnCreateNonceOnce("", errors.New("missing required fields in initial request"))

	// when
	response, err := server.SendNonGeneralRequest(t, initialRequest.AuthMessage())

	// then
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, response.StatusCode, "Response should be HTTP 400 Bad Request")

	bodyBytes, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	bodyStr := string(bodyBytes)

	t.Logf("Actual error response: %s", bodyStr)

	require.Contains(t, bodyStr, "Invalid nonce", "Response should indicate an invalid nonce")
}

func TestHandshake_UnsupportedVersion(t *testing.T) {
	// given
	sessionManager := mocks.NewMockableSessionManager()
	serverWallet := mocks.NewMockableWallet()
	server := mocks.CreateMockHTTPServer(serverWallet, sessionManager, mocks.WithLogger).
		WithHandler("/", mocks.IndexHandler().WithAuthMiddleware())
	defer server.Close()

	clientWallet := mocks.CreateClientMockWallet()

	initialRequest := mocks.PrepareInitialRequestBody(t.Context(), clientWallet)
	initialRequest.Version = "0.2" // Use unsupported version (0.1 is supported)

	// when
	response, err := server.SendNonGeneralRequest(t, initialRequest.AuthMessage())

	// then
	require.NoError(t, err)
	require.Equal(t, http.StatusInternalServerError, response.StatusCode, "Response should be HTTP 500 Internal Server Error")

	bodyBytes, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	bodyStr := string(bodyBytes)

	t.Logf("Actual error response: %s", bodyStr)
}

func TestHandshake_InvalidNonceFormat(t *testing.T) {
	// given
	sessionManager := mocks.NewMockableSessionManager()
	serverWallet := mocks.NewMockableWallet()
	server := mocks.CreateMockHTTPServer(serverWallet, sessionManager, mocks.WithLogger).
		WithHandler("/", mocks.IndexHandler().WithAuthMiddleware())
	defer server.Close()

	clientWallet := mocks.CreateClientMockWallet()

	initialRequest := mocks.PrepareInitialRequestBody(t.Context(), clientWallet)
	initialRequest.InitialNonce = "this-is-not-valid-base64!"

	serverWallet.OnCreateNonceOnce("", errors.New("invalid nonce format"))
	serverWallet.OnCreateHmacOnce(&wallet.CreateHmacResult{
		Hmac: []byte("mockhmacsignature"),
	}, nil)

	// when
	response, err := server.SendNonGeneralRequest(t, initialRequest.AuthMessage())

	// then
	require.NoError(t, err)
	require.Equal(t, 500, response.StatusCode, "Status code should be 500")
}
