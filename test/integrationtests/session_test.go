package integrationtests

import (
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/temporary/sessionmanager"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/temporary/wallet"
	walletFixtures "github.com/bsv-blockchain/go-bsv-middleware/pkg/temporary/wallet/test"
	"github.com/bsv-blockchain/go-bsv-middleware/test/assert"
	"github.com/bsv-blockchain/go-bsv-middleware/test/mocks"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/stretchr/testify/require"
)

func TestSessionCreationOnHandshake(t *testing.T) {
	// given
	sessionManager := mocks.NewMockableSessionManager()
	serverWallet := mocks.NewMockableWallet()
	server := mocks.CreateMockHTTPServer(serverWallet, sessionManager, mocks.WithLogger).
		WithHandler("/", mocks.IndexHandler().WithAuthMiddleware())
	defer server.Close()

	clientWallet := mocks.CreateClientMockWallet()
	initialRequest := mocks.PrepareInitialRequestBody(clientWallet)

	serverWallet.OnCreateNonceOnce(walletFixtures.DefaultNonces[0], nil)
	serverWallet.OnCreateSignatureOnce(prepareExampleSignature(t), nil)
	serverWallet.OnGetPublicKeyOnce(prepareExampleIdentityKey(t), nil)

	// when
	response, err := server.SendNonGeneralRequest(t, initialRequest.AuthMessage())

	// then
	require.NoError(t, err)
	assert.ResponseOK(t, response)

	session := sessionManager.GetSession(initialRequest.IdentityKey)
	require.NotNil(t, session)
	require.Equal(t, initialRequest.InitialNonce, *session.PeerNonce)
	require.Equal(t, initialRequest.IdentityKey, *session.PeerIdentityKey)
	require.NotNil(t, session.SessionNonce)
	require.WithinDuration(t, time.Now(), session.LastUpdate, 5*time.Second)
}

func TestSessionAuthenticationAfterHandshake(t *testing.T) {
	// given
	sessionManager := sessionmanager.NewSessionManager()
	key, err := ec.PrivateKeyFromHex(walletFixtures.ServerPrivateKeyHex)
	require.NoError(t, err)
	serverWallet := wallet.NewMockWallet(key, walletFixtures.DefaultNonces...)

	server := mocks.CreateMockHTTPServer(serverWallet, sessionManager, mocks.WithLogger).
		WithHandler("/", mocks.IndexHandler().WithAuthMiddleware()).
		WithHandler("/ping", mocks.PingHandler().WithAuthMiddleware())
	defer server.Close()

	clientKey, err := ec.PrivateKeyFromHex(walletFixtures.ClientPrivateKeyHex)
	require.NoError(t, err)
	clientWallet := wallet.NewMockWallet(clientKey, walletFixtures.ClientNonces...)

	initialRequest := mocks.PrepareInitialRequestBody(clientWallet)

	response, err := server.SendNonGeneralRequest(t, initialRequest.AuthMessage())
	require.NoError(t, err)
	assert.ResponseOK(t, response)

	authMessage, err := mocks.MapBodyToAuthMessage(t, response)
	require.NoError(t, err)

	identityKey, err := clientWallet.GetPublicKey(&wallet.GetPublicKeyArgs{IdentityKey: true}, "")
	require.NoError(t, err)
	idKey := identityKey.PublicKey.ToDERHex()

	session := sessionManager.GetSession(idKey)
	require.NotNil(t, session)
	require.True(t, session.IsAuthenticated)

	originalTimestamp := session.LastUpdate

	// when
	pingURL := server.URL() + "/ping"

	request, err := http.NewRequest(http.MethodGet, pingURL, nil)
	require.NoError(t, err)
	err = mocks.PrepareGeneralRequestHeaders(clientWallet, authMessage, request)
	require.NoError(t, err)

	generalResponse, err := server.SendGeneralRequest(t, request)

	// then
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, generalResponse.StatusCode)

	body, err := io.ReadAll(generalResponse.Body)
	require.NoError(t, err)
	require.Equal(t, "Pong!", string(body))

	updatedSession := sessionManager.GetSession(idKey)
	require.NotNil(t, updatedSession)
	require.True(t, updatedSession.IsAuthenticated)
	require.True(t, updatedSession.LastUpdate.After(originalTimestamp))
}

func TestMultipleSessionsPerIdentityKey(t *testing.T) {
	// given
	sm := sessionmanager.NewSessionManager()
	identityKey := "0353854510f675922eb4d1ed3fd044c54d161c85852be5bf8074a8a8b1f2ee5273"

	nonce1 := "firstNonce"
	sessionNonce1 := "sessionNonce1"
	session1 := sessionmanager.PeerSession{
		IsAuthenticated: false,
		SessionNonce:    &sessionNonce1,
		PeerNonce:       &nonce1,
		PeerIdentityKey: &identityKey,
		LastUpdate:      time.Now().Add(-1 * time.Hour),
	}
	sm.AddSession(session1)

	nonce2 := "secondNonce"
	sessionNonce2 := "sessionNonce2"
	session2 := sessionmanager.PeerSession{
		IsAuthenticated: false,
		SessionNonce:    &sessionNonce2,
		PeerNonce:       &nonce2,
		PeerIdentityKey: &identityKey,
		LastUpdate:      time.Now(),
	}
	sm.AddSession(session2)

	// when
	s1 := sm.GetSession(sessionNonce1)
	s2 := sm.GetSession(sessionNonce2)
	byIdentity := sm.GetSession(identityKey)

	// then
	require.NotNil(t, s1)
	require.Equal(t, nonce1, *s1.PeerNonce)

	require.NotNil(t, s2)
	require.Equal(t, nonce2, *s2.PeerNonce)

	require.NotNil(t, byIdentity)
	require.Equal(t, *session2.SessionNonce, *byIdentity.SessionNonce)

	// when
	session1.IsAuthenticated = true
	sm.UpdateSession(session1)
	byIdentityAfterAuth := sm.GetSession(identityKey)

	// then
	require.NotNil(t, byIdentityAfterAuth)
	require.Equal(t, *session1.SessionNonce, *byIdentityAfterAuth.SessionNonce)

	// when
	session2.IsAuthenticated = true
	sm.UpdateSession(session2)
	byIdentityBothAuth := sm.GetSession(identityKey)

	// then
	require.NotNil(t, byIdentityBothAuth)
	require.Equal(t, *session2.SessionNonce, *byIdentityBothAuth.SessionNonce)
}

func TestSessionLookupFailure(t *testing.T) {
	// given
	sm := sessionmanager.NewSessionManager()
	nonExistentSessionNonce := "nonexistent-session-nonce"
	nonExistentIdentityKey := "nonexistent-identity-key"

	// when
	result1 := sm.GetSession(nonExistentSessionNonce)
	result2 := sm.GetSession(nonExistentIdentityKey)

	// then
	require.Nil(t, result1)
	require.Nil(t, result2)

	// when
	fakeSession := sessionmanager.PeerSession{
		SessionNonce:    &nonExistentSessionNonce,
		PeerIdentityKey: &nonExistentIdentityKey,
	}
	sm.RemoveSession(fakeSession)

	result3 := sm.GetSession(nonExistentSessionNonce)

	// then
	require.Nil(t, result3)
}

func TestSessionLastUpdateTracking(t *testing.T) {
	// given
	sm := sessionmanager.NewSessionManager()
	identityKey := "0353854510f675922eb4d1ed3fd044c54d161c85852be5bf8074a8a8b1f2ee5273"
	nonce := "testNonce"
	sessionNonce := "sessionNonce"

	initialTimestamp := time.Now().Add(-1 * time.Hour)
	session := sessionmanager.PeerSession{
		IsAuthenticated: false,
		SessionNonce:    &sessionNonce,
		PeerNonce:       &nonce,
		PeerIdentityKey: &identityKey,
		LastUpdate:      initialTimestamp,
	}

	sm.AddSession(session)

	// when
	retrievedSession := sm.GetSession(sessionNonce)

	// then
	require.NotNil(t, retrievedSession)
	require.WithinDuration(t, initialTimestamp, retrievedSession.LastUpdate, time.Millisecond)

	// when
	time.Sleep(10 * time.Millisecond)
	updatedTimestamp := time.Now()
	session.LastUpdate = updatedTimestamp
	sm.UpdateSession(session)
	updatedSession := sm.GetSession(sessionNonce)

	// then
	require.NotNil(t, updatedSession)
	require.WithinDuration(t, updatedTimestamp, updatedSession.LastUpdate, time.Millisecond)
	require.True(t, updatedSession.LastUpdate.After(initialTimestamp))
}
