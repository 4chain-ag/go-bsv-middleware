package integrationtests

import (
	"net/http"
	"testing"

	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
	"github.com/4chain-ag/go-bsv-middleware/pkg/test/assert"
	"github.com/4chain-ag/go-bsv-middleware/pkg/test/mocks"
	"github.com/4chain-ag/go-bsv-middleware/pkg/transport"
	"github.com/stretchr/testify/require"
)

func TestAuthMiddleware_Handshake_HappyPath(t *testing.T) {
	// given
	server := mocks.CreateMockHTTPServer(mocks.WithLogger).
		WithHandler("/", mocks.IndexHandler().WithAuthMiddleware()).
		WithHandler("/ping", mocks.PingHandler().WithAuthMiddleware())
	defer server.Close()

	clientWallet := mocks.CreateClientMockWallet()

	var testState struct {
		rAuthMessage *transport.AuthMessage
	}

	pingPath := server.URL() + "/ping"

	t.Run("call initial request", func(t *testing.T) {
		// given
		initialRequest := mocks.PrepareInitialRequestBody(clientWallet)

		// when
		response, err := server.SendNonGeneralRequest(t, initialRequest.AuthMessage())

		// then
		require.NoError(t, err)
		assert.ResponseOK(t, response)
		assert.InitialResponseHeaders(t, response)

		authMessage, err := mocks.MapBodyToAuthMessage(t, response)
		require.NoError(t, err)
		assert.InitialResponseAuthMessage(t, authMessage)

		testState.rAuthMessage = authMessage
	})

	t.Run("check authorization with GET", func(t *testing.T) {
		// given
		request, err := http.NewRequest(http.MethodGet, pingPath, nil)
		require.NoError(t, err)
		err = mocks.PrepareGeneralRequestHeaders(clientWallet, testState.rAuthMessage, request)
		require.NoError(t, err)

		// when
		response, err := server.SendGeneralRequest(t, request)

		// then
		require.NoError(t, err)
		assert.ResponseOK(t, response)
		assert.GeneralResponseHeaders(t, response, 0)
	})

	t.Run("check authorization with POST", func(t *testing.T) {
		// given
		request, err := http.NewRequest(http.MethodPost, pingPath, nil)
		require.NoError(t, err)
		err = mocks.PrepareGeneralRequestHeaders(clientWallet, testState.rAuthMessage, request)
		require.NoError(t, err)

		// when
		response, err := server.SendGeneralRequest(t, request)

		// then
		require.NoError(t, err)
		assert.ResponseOK(t, response)
		assert.GeneralResponseHeaders(t, response, 1)
	})

	t.Run("check authorization with PUT", func(t *testing.T) {
		// given
		request, err := http.NewRequest(http.MethodPut, pingPath, nil)
		require.NoError(t, err)
		err = mocks.PrepareGeneralRequestHeaders(clientWallet, testState.rAuthMessage, request)
		require.NoError(t, err)

		// when
		response, err := server.SendGeneralRequest(t, request)

		// then
		require.NoError(t, err)
		assert.ResponseOK(t, response)
		assert.GeneralResponseHeaders(t, response, 2)
	})

	t.Run("check authorization with DELETE", func(t *testing.T) {
		// given
		request, err := http.NewRequest(http.MethodDelete, pingPath, nil)
		require.NoError(t, err)
		err = mocks.PrepareGeneralRequestHeaders(clientWallet, testState.rAuthMessage, request)
		require.NoError(t, err)

		// when
		response, err := server.SendGeneralRequest(t, request)

		// then
		require.NoError(t, err)
		assert.ResponseOK(t, response)
		assert.GeneralResponseHeaders(t, response, 3)
	})
}

func TestAuthMiddleware_NonGeneralRequest_ErrorPath(t *testing.T) {
	// given
	server := mocks.CreateMockHTTPServer(mocks.WithLogger).
		WithHandler("/", mocks.IndexHandler().WithAuthMiddleware()).
		WithHandler("/ping", mocks.PingHandler().WithAuthMiddleware())
	defer server.Close()

	clientWallet := mocks.CreateClientMockWallet()

	t.Run("wrong version", func(t *testing.T) {
		// given
		initialRequest := mocks.PrepareInitialRequestBody(clientWallet).WithWrongVersion()

		// when
		response, err := server.SendNonGeneralRequest(t, initialRequest.AuthMessage())

		// then
		require.NoError(t, err)
		assert.NotAuthorized(t, response)
		assert.UnsupportedVersionError(t, response)
	})

	t.Run("missing identity key and initial nonce", func(t *testing.T) {
		// given
		initialRequest := mocks.PrepareInitialRequestBody(clientWallet).WithoutIdentityKeyAndNonce()

		// when
		response, err := server.SendNonGeneralRequest(t, initialRequest.AuthMessage())

		// then
		require.NoError(t, err)
		assert.NotAuthorized(t, response)
		assert.MissingRequiredFieldsError(t, response)
	})
}

func TestAuthMiddleware_GeneralRequest_ErrorPath(t *testing.T) {
	// given
	server := mocks.CreateMockHTTPServer(mocks.WithLogger).
		WithHandler("/", mocks.IndexHandler().WithAuthMiddleware()).
		WithHandler("/ping", mocks.PingHandler().WithAuthMiddleware())
	defer server.Close()

	clientWallet := mocks.CreateClientMockWallet()

	var testState struct {
		rAuthMessage *transport.AuthMessage
	}

	pingPath := server.URL() + "/ping"

	t.Run("no auth headers", func(t *testing.T) {
		// given
		request, err := http.NewRequest(http.MethodGet, pingPath, nil)
		require.NoError(t, err)

		// when
		response, err := server.SendGeneralRequest(t, request)

		// then
		require.NoError(t, err)
		assert.NotAuthorized(t, response)
		assert.MissingRequestIDError(t, response)
	})

	t.Run("wrong signature", func(t *testing.T) {
		// given
		rAuthMessage := prepareSession(t, clientWallet, server)
		testState.rAuthMessage = rAuthMessage

		request, err := http.NewRequest(http.MethodGet, pingPath, nil)
		require.NoError(t, err)
		err = mocks.PrepareGeneralRequestHeaders(clientWallet, testState.rAuthMessage, request, mocks.WithWrongSignature)
		require.NoError(t, err)

		// when
		response, err := server.SendGeneralRequest(t, request)

		// then
		require.NoError(t, err)
		assert.NotAuthorized(t, response)
		assert.DecodingSignatureError(t, response)
	})

	t.Run("wrong version", func(t *testing.T) {
		// given
		request, err := http.NewRequest(http.MethodGet, pingPath, nil)
		require.NoError(t, err)
		err = mocks.PrepareGeneralRequestHeaders(clientWallet, testState.rAuthMessage, request, mocks.WithWrongVersion)
		require.NoError(t, err)

		// when
		response, err := server.SendGeneralRequest(t, request)

		// then
		require.NoError(t, err)
		assert.NotAuthorized(t, response)
		assert.UnsupportedVersionError(t, response)
	})

	t.Run("wrong your nonce", func(t *testing.T) {
		// given
		request, err := http.NewRequest(http.MethodGet, pingPath, nil)
		require.NoError(t, err)
		err = mocks.PrepareGeneralRequestHeaders(clientWallet, testState.rAuthMessage, request, mocks.WithWrongYourNonce)
		require.NoError(t, err)

		// when
		response, err := server.SendGeneralRequest(t, request)

		// then
		require.NoError(t, err)
		assert.NotAuthorized(t, response)
		assert.UnableToVerifyNonceError(t, response)
	})

	t.Run("wrong signature - unable to decode", func(t *testing.T) {
		// given
		request, err := http.NewRequest(http.MethodGet, pingPath, nil)
		require.NoError(t, err)
		err = mocks.PrepareGeneralRequestHeaders(clientWallet, testState.rAuthMessage, request, mocks.WithWrongSignatureInHex)
		require.NoError(t, err)

		// when
		response, err := server.SendGeneralRequest(t, request)

		// then
		require.NoError(t, err)
		assert.NotAuthorized(t, response)
		assert.UnableToVerifySignatureError(t, response)
	})

	t.Run("wrong signature - unable to decode", func(t *testing.T) {
		// given
		request, err := http.NewRequest(http.MethodGet, pingPath, nil)
		require.NoError(t, err)
		err = mocks.PrepareGeneralRequestHeaders(clientWallet, testState.rAuthMessage, request, mocks.WithWrongSignatureInHex)
		require.NoError(t, err)

		// when
		response, err := server.SendGeneralRequest(t, request)

		// then
		require.NoError(t, err)
		assert.NotAuthorized(t, response)
		assert.UnableToVerifySignatureError(t, response)
	})
}

func TestAuthMiddleware_WithAllowUnauthenticated_HappyPath(t *testing.T) {
	// given
	server := mocks.CreateMockHTTPServer(mocks.WithLogger, mocks.WithAllowUnauthenticated).
		WithHandler("/", mocks.IndexHandler().WithAuthMiddleware()).
		WithHandler("/ping", mocks.PingHandler().WithAuthMiddleware())
	defer server.Close()

	pingPath := server.URL() + "/ping"

	t.Run("without headers", func(t *testing.T) {
		// given
		request, err := http.NewRequest(http.MethodGet, pingPath, nil)
		require.NoError(t, err)

		// when
		response, err := server.SendGeneralRequest(t, request)

		// then
		require.NoError(t, err)
		assert.ResponseOK(t, response)
		require.Equal(t, 200, response.StatusCode)
	})
}

func prepareSession(t *testing.T, clientWallet wallet.WalletInterface, server *mocks.MockHTTPServer) *transport.AuthMessage {
	initialRequest := mocks.PrepareInitialRequestBody(clientWallet)
	response, err := server.SendNonGeneralRequest(t, initialRequest.AuthMessage())
	require.NoError(t, err)
	assert.ResponseOK(t, response)
	assert.InitialResponseHeaders(t, response)

	authMessage, err := mocks.MapBodyToAuthMessage(t, response)
	require.NoError(t, err)
	assert.InitialResponseAuthMessage(t, authMessage)

	return authMessage
}
