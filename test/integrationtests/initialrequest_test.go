package integrationtests

import (
	"testing"

	"github.com/bsv-blockchain/go-bsv-middleware/test/assert"
	"github.com/bsv-blockchain/go-bsv-middleware/test/mocks"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
)

func TestAuthMiddleware_InitialRequest_HappyPath(t *testing.T) {
	// given
	sessionManager := mocks.NewMockableSessionManager()
	serverWallet := mocks.NewMockableWallet()
	server := mocks.CreateMockHTTPServer(serverWallet, sessionManager, mocks.WithLogger).
		WithHandler("/", mocks.IndexHandler().WithAuthMiddleware()).
		WithHandler("/ping", mocks.PingHandler().WithAuthMiddleware())
	defer server.Close()

	clientWallet := mocks.CreateClientMockWallet()

	t.Run("call initial request", func(t *testing.T) {
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
	})

}

func prepareExampleSignature(t *testing.T) *wallet.CreateSignatureResult {
	key, err := ec.PrivateKeyFromHex(mocks.ServerPrivateKeyHex)
	require.NoError(t, err)
	signature, err := key.Sign([]byte("test signature"))
	require.NoError(t, err)

	return &wallet.CreateSignatureResult{Signature: *signature}
}

func prepareExampleIdentityKey(t *testing.T) *wallet.GetPublicKeyResult {
	key, err := ec.PrivateKeyFromHex(mocks.ServerPrivateKeyHex)
	require.NoError(t, err)
	return &wallet.GetPublicKeyResult{
		PublicKey: key.PubKey(),
	}
}
