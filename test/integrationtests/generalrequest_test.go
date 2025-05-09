package integrationtests

import (
	"net/http"
	"testing"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/interfaces"
	"github.com/bsv-blockchain/go-bsv-middleware/test/assert"
	"github.com/bsv-blockchain/go-bsv-middleware/test/mocks"
	"github.com/bsv-blockchain/go-sdk/auth"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
)

func TestAuthMiddleware_GeneralRequest_AllowUnauthenticated(t *testing.T) {
	// given
	sessionManager := mocks.NewMockableSessionManager()
	serverWallet := mocks.NewMockableWallet()

	t.Run("call general request without auth headers - allowUnauthenticated=false", func(t *testing.T) {
		// given
		server := mocks.CreateMockHTTPServer(serverWallet, sessionManager, mocks.WithLogger).
			WithHandler("/", mocks.IndexHandler().WithAuthMiddleware()).
			WithHandler("/ping", mocks.PingHandler().WithAuthMiddleware())
		defer server.Close()
		pingPath := server.URL() + "/ping"

		request, err := http.NewRequest(http.MethodGet, pingPath, nil)
		require.NoError(t, err)

		// when
		response, err := server.SendGeneralRequest(t, request)

		// then
		require.NoError(t, err)
		assert.NotAuthorized(t, response)
		assert.MissingRequestIDError(t, response)
	})

	t.Run("call general request without auth headers - allowUnauthenticated=true", func(t *testing.T) {
		// given
		server := mocks.CreateMockHTTPServer(serverWallet, sessionManager, mocks.WithLogger, mocks.WithAllowUnauthenticated).
			WithHandler("/", mocks.IndexHandler().WithAuthMiddleware()).
			WithHandler("/ping", mocks.PingHandler().WithAuthMiddleware())
		defer server.Close()
		pingPath := server.URL() + "/ping"

		request, err := http.NewRequest(http.MethodGet, pingPath, nil)
		require.NoError(t, err)

		// when
		response, err := server.SendGeneralRequest(t, request)

		// then
		require.NoError(t, err)
		assert.ResponseOK(t, response)
	})
}

func TestAuthMiddleware_GeneralRequest_Signature(t *testing.T) {
	// given
	sessionManager := mocks.NewMockableSessionManager()
	serverWallet := mocks.NewMockableWallet()
	server := mocks.CreateMockHTTPServer(serverWallet, sessionManager, mocks.WithLogger).
		WithHandler("/", mocks.IndexHandler().WithAuthMiddleware()).
		WithHandler("/ping", mocks.PingHandler().WithAuthMiddleware())
	defer server.Close()

	clientWallet := mocks.CreateClientMockWallet()
	authMessage := prepareInitialRequest(t, serverWallet, clientWallet, server)

	pingPath := server.URL() + "/ping"

	t.Run("verify signature fail", func(t *testing.T) {
		// given
		request, err := http.NewRequest(http.MethodGet, pingPath, nil)
		require.NoError(t, err)
		err = mocks.PrepareGeneralRequestHeaders(t.Context(), clientWallet, authMessage, request)
		require.NoError(t, err)

		serverWallet.OnVerifyNonceOnce(true, nil)
		serverWallet.OnVerifySignatureOnce(&wallet.VerifySignatureResult{Valid: false}, nil)

		// when
		response, err := server.SendGeneralRequest(t, request)

		// then
		require.NoError(t, err)
		assert.NotAuthorized(t, response)
		assert.UnableToVerifySignatureError(t, response)
	})
}

func TestAuthMiddleware_GeneralRequest_SessionManager(t *testing.T) {
	// given
	sessionManager := mocks.NewMockableSessionManager()
	serverWallet := mocks.NewMockableWallet()
	server := mocks.CreateMockHTTPServer(serverWallet, sessionManager, mocks.WithLogger).
		WithHandler("/", mocks.IndexHandler().WithAuthMiddleware()).
		WithHandler("/ping", mocks.PingHandler().WithAuthMiddleware())
	defer server.Close()

	clientWallet := mocks.CreateClientMockWallet()
	authMessage := prepareInitialRequest(t, serverWallet, clientWallet, server)

	pingPath := server.URL() + "/ping"

	t.Run("session not found", func(t *testing.T) {
		// given
		request, err := http.NewRequest(http.MethodGet, pingPath, nil)
		require.NoError(t, err)
		err = mocks.PrepareGeneralRequestHeaders(t.Context(), clientWallet, authMessage, request)
		require.NoError(t, err)

		serverWallet.OnVerifyNonceOnce(true, nil)
		sessionManager.OnGetSessionOnce(authMessage.InitialNonce, nil)

		// when
		response, err := server.SendGeneralRequest(t, request)

		// then
		require.NoError(t, err)
		assert.NotAuthorized(t, response)
		assert.SessionNotFoundError(t, response)
	})

	t.Run("session not authenticated", func(t *testing.T) {
		// given
		request, err := http.NewRequest(http.MethodGet, pingPath, nil)
		require.NoError(t, err)
		err = mocks.PrepareGeneralRequestHeaders(t.Context(), clientWallet, authMessage, request)
		require.NoError(t, err)

		serverWallet.OnVerifyNonceOnce(true, nil)
		sessionManager.OnGetSessionOnce(authMessage.InitialNonce, &auth.PeerSession{IsAuthenticated: false})

		// when
		response, err := server.SendGeneralRequest(t, request)

		// then
		require.NoError(t, err)
		assert.NotAuthorized(t, response)
		assert.SessionNotAuthenticatedError(t, response)
	})
}

func TestAuthMiddleware_GeneralRequest_HeaderValidation(t *testing.T) {
	// given
	sessionManager := mocks.NewMockableSessionManager()
	serverWallet := mocks.NewMockableWallet()
	server := mocks.CreateMockHTTPServer(serverWallet, sessionManager, mocks.WithLogger).
		WithHandler("/", mocks.IndexHandler().WithAuthMiddleware()).
		WithHandler("/ping", mocks.PingHandler().WithAuthMiddleware())
	defer server.Close()

	clientWallet := mocks.CreateClientMockWallet()
	authMessage := prepareInitialRequest(t, serverWallet, clientWallet, server)

	pingPath := server.URL() + "/ping"

	t.Run("no version header", func(t *testing.T) {
		// given
		request, err := http.NewRequest(http.MethodGet, pingPath, nil)
		require.NoError(t, err)
		err = mocks.PrepareGeneralRequestHeaders(t.Context(), clientWallet, authMessage, request)
		require.NoError(t, err)
		request.Header.Del("x-bsv-auth-version")

		// when
		response, err := server.SendGeneralRequest(t, request)

		// then
		require.NoError(t, err)
		assert.NotAuthorized(t, response)
		assert.MissingHeaderError(t, response, "version")
	})

	t.Run("no identity key", func(t *testing.T) {
		// given
		request, err := http.NewRequest(http.MethodGet, pingPath, nil)
		require.NoError(t, err)
		err = mocks.PrepareGeneralRequestHeaders(t.Context(), clientWallet, authMessage, request)
		require.NoError(t, err)
		request.Header.Del("x-bsv-auth-identity-key")

		// when
		response, err := server.SendGeneralRequest(t, request)

		// then
		require.NoError(t, err)
		assert.NotAuthorized(t, response)
		assert.MissingHeaderError(t, response, "identity key")
	})

	t.Run("no nonce", func(t *testing.T) {
		// given
		request, err := http.NewRequest(http.MethodGet, pingPath, nil)
		require.NoError(t, err)
		err = mocks.PrepareGeneralRequestHeaders(t.Context(), clientWallet, authMessage, request)
		require.NoError(t, err)
		request.Header.Del("x-bsv-auth-nonce")

		// when
		response, err := server.SendGeneralRequest(t, request)

		// then
		require.NoError(t, err)
		assert.NotAuthorized(t, response)
		assert.MissingHeaderError(t, response, "nonce")
	})

	t.Run("no your nonce", func(t *testing.T) {
		// given
		request, err := http.NewRequest(http.MethodGet, pingPath, nil)
		require.NoError(t, err)
		err = mocks.PrepareGeneralRequestHeaders(t.Context(), clientWallet, authMessage, request)
		require.NoError(t, err)
		request.Header.Del("x-bsv-auth-your-nonce")

		// when
		response, err := server.SendGeneralRequest(t, request)

		// then
		require.NoError(t, err)
		assert.NotAuthorized(t, response)
		assert.MissingHeaderError(t, response, "your nonce")
	})

	t.Run("no signature", func(t *testing.T) {
		// given
		request, err := http.NewRequest(http.MethodGet, pingPath, nil)
		require.NoError(t, err)
		err = mocks.PrepareGeneralRequestHeaders(t.Context(), clientWallet, authMessage, request)
		require.NoError(t, err)
		request.Header.Del("x-bsv-auth-signature")

		// when
		response, err := server.SendGeneralRequest(t, request)

		// then
		require.NoError(t, err)
		assert.NotAuthorized(t, response)
		assert.MissingHeaderError(t, response, "signature")
	})

	t.Run("wrong signature format", func(t *testing.T) {
		// given
		request, err := http.NewRequest(http.MethodGet, pingPath, nil)
		require.NoError(t, err)
		err = mocks.PrepareGeneralRequestHeaders(t.Context(), clientWallet, authMessage, request, mocks.WithWrongSignature)
		require.NoError(t, err)

		// when
		response, err := server.SendGeneralRequest(t, request)

		// then
		require.NoError(t, err)
		assert.NotAuthorized(t, response)
		assert.InvalidHeaderError(t, response, "signature")
	})

	t.Run("wrong nonce format", func(t *testing.T) {
		// given
		request, err := http.NewRequest(http.MethodGet, pingPath, nil)
		require.NoError(t, err)
		err = mocks.PrepareGeneralRequestHeaders(t.Context(), clientWallet, authMessage, request, mocks.WithWrongNonce)
		require.NoError(t, err)

		// when
		response, err := server.SendGeneralRequest(t, request)

		// then
		require.NoError(t, err)
		assert.NotAuthorized(t, response)
		assert.InvalidHeaderError(t, response, "nonce")
	})

	t.Run("wrong your nonce format", func(t *testing.T) {
		// given
		request, err := http.NewRequest(http.MethodGet, pingPath, nil)
		require.NoError(t, err)
		err = mocks.PrepareGeneralRequestHeaders(t.Context(), clientWallet, authMessage, request, mocks.WithWrongYourNonce)
		require.NoError(t, err)

		// when
		response, err := server.SendGeneralRequest(t, request)

		// then
		require.NoError(t, err)
		assert.NotAuthorized(t, response)
		assert.InvalidHeaderError(t, response, "your nonce")
	})

	t.Run("wrong version", func(t *testing.T) {
		// given
		request, err := http.NewRequest(http.MethodGet, pingPath, nil)
		require.NoError(t, err)
		err = mocks.PrepareGeneralRequestHeaders(t.Context(), clientWallet, authMessage, request, mocks.WithWrongVersion)
		require.NoError(t, err)

		// when
		response, err := server.SendGeneralRequest(t, request)

		// then
		require.NoError(t, err)
		assert.NotAuthorized(t, response)
		assert.UnsupportedVersionError(t, response)
	})
}

func prepareInitialRequest(
	t *testing.T,
	serverWallet *mocks.MockableWallet,
	clientWallet interfaces.Wallet,
	server *mocks.MockHTTPServer) *auth.AuthMessage {

	// given
	initialRequest := mocks.PrepareInitialRequestBody(t.Context(), clientWallet)
	serverWallet.OnCreateNonceOnce(mocks.DefaultNonces[0], nil)
	serverWallet.OnCreateSignatureOnce(prepareExampleSignature(t), nil)
	serverWallet.OnGetPublicKeyOnce(prepareExampleIdentityKey(t), nil)

	// when
	response, err := server.SendNonGeneralRequest(t, initialRequest.AuthMessage())

	// then
	require.NoError(t, err)
	assert.ResponseOK(t, response)
	assert.InitialResponseHeaders(t, response)

	authMessage, err := mocks.MapBodyToAuthMessage(t, response)
	require.NoError(t, err)
	assert.InitialResponseAuthMessage(t, authMessage)

	return authMessage
}
