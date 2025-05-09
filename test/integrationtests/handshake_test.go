package integrationtests

import (
	"errors"
	"testing"

	"github.com/bsv-blockchain/go-bsv-middleware/test/assert"
	"github.com/bsv-blockchain/go-bsv-middleware/test/mocks"
	"github.com/stretchr/testify/require"
)

func TestHandshakeHappyPath(t *testing.T) {
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

	// when
	response, err := server.SendNonGeneralRequest(t, initialRequest.AuthMessage())

	// then
	require.NoError(t, err)
	assert.ResponseOK(t, response)
	assert.InitialResponseHeaders(t, response)

	authMessage, err := mocks.MapBodyToAuthMessage(t, response)
	require.NoError(t, err)
	assert.InitialResponseAuthMessage(t, authMessage)

	session, err := sessionManager.GetSession(initialRequest.IdentityKey.ToDERHex())
	require.NoError(t, err)
	require.NotNil(t, session, "Session should have been created with client's identity key")
	require.Equal(t, initialRequest.InitialNonce, session.PeerNonce, "Session nonce should match")
}

func TestMissingRequiredFields(t *testing.T) {
	// given
	sessionManager := mocks.NewMockableSessionManager()
	serverWallet := mocks.NewMockableWallet()
	server := mocks.CreateMockHTTPServer(serverWallet, sessionManager, mocks.WithLogger).
		WithHandler("/", mocks.IndexHandler().WithAuthMiddleware())
	defer server.Close()

	clientWallet := mocks.CreateClientMockWallet()

	t.Run("missing identity key", func(t *testing.T) {
		// given
		initialRequest := mocks.PrepareInitialRequestBody(t.Context(), clientWallet)
		initialRequest.IdentityKey = nil

		serverWallet.OnCreateNonceOnce("", errors.New("missing required fields in initial request"))

		// when
		response, err := server.SendNonGeneralRequest(t, initialRequest.AuthMessage())

		// then
		require.NoError(t, err)
		assert.NotAuthorized(t, response)
		assert.MissingRequiredFieldsError(t, response)
	})

	t.Run("missing initial nonce", func(t *testing.T) {
		// given
		initialRequest := mocks.PrepareInitialRequestBody(t.Context(), clientWallet)
		initialRequest.InitialNonce = ""

		serverWallet.OnCreateNonceOnce("", errors.New("missing required fields in initial request"))

		// when
		response, err := server.SendNonGeneralRequest(t, initialRequest.AuthMessage())

		// then
		require.NoError(t, err)
		assert.NotAuthorized(t, response)
		assert.MissingRequiredFieldsError(t, response)
	})

	t.Run("missing both fields", func(t *testing.T) {
		// given
		initialRequest := mocks.PrepareInitialRequestBody(t.Context(), clientWallet)
		initialRequest.IdentityKey = nil
		initialRequest.InitialNonce = ""

		// when
		response, err := server.SendNonGeneralRequest(t, initialRequest.AuthMessage())

		// then
		require.NoError(t, err)
		assert.NotAuthorized(t, response)
		assert.MissingRequiredFieldsError(t, response)
	})
}

func TestUnsupportedVersion(t *testing.T) {
	// given
	sessionManager := mocks.NewMockableSessionManager()
	serverWallet := mocks.NewMockableWallet()
	server := mocks.CreateMockHTTPServer(serverWallet, sessionManager, mocks.WithLogger).
		WithHandler("/", mocks.IndexHandler().WithAuthMiddleware())
	defer server.Close()

	clientWallet := mocks.CreateClientMockWallet()
	initialRequest := mocks.PrepareInitialRequestBody(t.Context(), clientWallet)
	initialRequest.Version = "0.2"

	// when
	response, err := server.SendNonGeneralRequest(t, initialRequest.AuthMessage())

	// then
	require.NoError(t, err)
	assert.NotAuthorized(t, response)
	assert.UnsupportedVersionError(t, response)
}

func TestInvalidNonceFormat(t *testing.T) {
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

	// when
	response, err := server.SendNonGeneralRequest(t, initialRequest.AuthMessage())

	// then
	require.NoError(t, err)
	assert.NotAuthorized(t, response)
	assert.InvalidNonceFormatError(t, response)
}

func TestReplayAttack(t *testing.T) {
	// given
	sessionManager := mocks.NewMockableSessionManager()
	serverWallet := mocks.NewMockableWallet()
	server := mocks.CreateMockHTTPServer(serverWallet, sessionManager, mocks.WithLogger).
		WithHandler("/", mocks.IndexHandler().WithAuthMiddleware())
	defer server.Close()

	clientWallet := mocks.CreateClientMockWallet()
	initialRequest := mocks.PrepareInitialRequestBody(t.Context(), clientWallet)

	// First request should succeed
	serverWallet.OnCreateNonceOnce(mocks.DefaultNonces[0], nil)
	serverWallet.OnCreateSignatureOnce(prepareExampleSignature(t), nil)
	serverWallet.OnGetPublicKeyOnce(prepareExampleIdentityKey(t), nil)

	// when
	response, err := server.SendNonGeneralRequest(t, initialRequest.AuthMessage())

	// then
	require.NoError(t, err)
	assert.ResponseOK(t, response)

	sessionManager = mocks.NewMockableSessionManager()
	serverWallet = mocks.NewMockableWallet()
	server = mocks.CreateMockHTTPServer(serverWallet, sessionManager, mocks.WithLogger).
		WithHandler("/", mocks.IndexHandler().WithAuthMiddleware())

	// for the second request (replay attack), simulate returning an error about nonce already used
	serverWallet.OnCreateNonceOnce("", errors.New("nonce already used"))

	// when - sending the same request again
	response, err = server.SendNonGeneralRequest(t, initialRequest.AuthMessage())

	// then
	require.NoError(t, err)
	assert.NotAuthorized(t, response)
	assert.NonceAlreadyUsedError(t, response)
}
