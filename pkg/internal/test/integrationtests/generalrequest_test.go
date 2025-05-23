package integrationtests

import (
	"net/http"
	"testing"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/constants"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/test/mocks"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/test/testutils"
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
		testutils.NotAuthorized(t, response)
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
		testutils.ResponseOK(t, response)
	})
}

func TestAuthMiddleware_GeneralRequest_Signature(t *testing.T) {
	// given
	sessionManager := mocks.NewMockableSessionManager()
	serverWallet := mocks.NewMockableWallet()
	clientWallet := mocks.CreateClientMockWallet()
	server := mocks.CreateMockHTTPServer(serverWallet, sessionManager, mocks.WithLogger).
		WithHandler("/", mocks.IndexHandler().WithAuthMiddleware()).
		WithHandler("/ping", mocks.PingHandler().WithAuthMiddleware())
	defer server.Close()

	initialRequest := mocks.PrepareInitialRequestBody(t.Context(), clientWallet)

	serverWallet.OnGetPublicKeyOnce(prepareExampleIdentityKey(t), nil)
	serverWallet.OnCreateHmacOnce(&wallet.CreateHmacResult{
		Hmac: []byte("mockhmacsignature"),
	}, nil)
	serverWallet.OnCreateNonceOnce(mocks.DefaultNonces[0], nil)
	serverWallet.OnCreateSignatureOnce(prepareExampleSignature(t), nil)

	response, err := server.SendNonGeneralRequest(t, initialRequest.AuthMessage())
	require.NoError(t, err)
	testutils.ResponseOK(t, response)

	authMessage, err := mocks.MapBodyToAuthMessage(t, response)
	require.NoError(t, err)
	// when
	pingPath := server.URL() + "/ping"
	request, err := http.NewRequest(http.MethodGet, pingPath, nil)
	require.NoError(t, err)
	err = mocks.PrepareGeneralRequestHeaders(t.Context(), clientWallet, authMessage, request)
	require.NoError(t, err)
	serverWallet.OnVerifyNonceOnce(true, nil)
	serverWallet.OnVerifySignatureOnce(&wallet.VerifySignatureResult{Valid: false}, nil)
	sessionManager.OnGetSessionOnce("02ba6965682077505d33a05e2206007e4795c045faa439fc3629d05dfb50c0bcb1", &auth.PeerSession{
		IsAuthenticated: true,
		SessionNonce:    authMessage.InitialNonce,
		PeerNonce:       authMessage.YourNonce,
		PeerIdentityKey: initialRequest.IdentityKey,
		LastUpdate:      1747241090788,
	})
	response, err = server.SendGeneralRequest(t, request)

	// then
	require.NoError(t, err)
	testutils.InternalServerError(t, response)
}

func TestAuthMiddleware_GeneralRequest_SessionManager(t *testing.T) {
	t.Run("session not found", func(t *testing.T) {
		// given
		sessionManager := mocks.NewMockableSessionManager()
		serverWallet := mocks.NewMockableWallet()
		clientWallet := mocks.CreateClientMockWallet()
		server := mocks.CreateMockHTTPServer(serverWallet, sessionManager, mocks.WithLogger).
			WithHandler("/", mocks.IndexHandler().WithAuthMiddleware()).
			WithHandler("/ping", mocks.PingHandler().WithAuthMiddleware())
		defer server.Close()

		initialRequest := mocks.PrepareInitialRequestBody(t.Context(), clientWallet)

		serverWallet.OnGetPublicKeyOnce(prepareExampleIdentityKey(t), nil)
		serverWallet.OnCreateHmacOnce(&wallet.CreateHmacResult{
			Hmac: []byte("mockhmacsignature"),
		}, nil)
		serverWallet.OnCreateNonceOnce(mocks.DefaultNonces[0], nil)
		serverWallet.OnCreateSignatureOnce(prepareExampleSignature(t), nil)

		response, err := server.SendNonGeneralRequest(t, initialRequest.AuthMessage())
		require.NoError(t, err)
		testutils.ResponseOK(t, response)

		authMessage, err := mocks.MapBodyToAuthMessage(t, response)
		require.NoError(t, err)
		// when
		pingPath := server.URL() + "/ping"
		request, err := http.NewRequest(http.MethodGet, pingPath, nil)
		require.NoError(t, err)
		err = mocks.PrepareGeneralRequestHeaders(t.Context(), clientWallet, authMessage, request)
		require.NoError(t, err)
		serverWallet.OnVerifyNonceOnce(true, nil)
		serverWallet.OnVerifySignatureOnce(&wallet.VerifySignatureResult{Valid: false}, nil)
		sessionManager.OnGetSessionOnce("02ba6965682077505d33a05e2206007e4795c045faa439fc3629d05dfb50c0bcb1", nil)
		response, err = server.SendGeneralRequest(t, request)

		// then
		require.NoError(t, err)
		testutils.NotAuthorized(t, response)
		require.Contains(t, testutils.ReadBodyForTest(t, response), "session not found")
	})

	t.Run("session not authenticated", func(t *testing.T) {
		// given
		sessionManager := mocks.NewMockableSessionManager()
		serverWallet := mocks.NewMockableWallet()
		clientWallet := mocks.CreateClientMockWallet()
		server := mocks.CreateMockHTTPServer(serverWallet, sessionManager, mocks.WithLogger).
			WithHandler("/", mocks.IndexHandler().WithAuthMiddleware()).
			WithHandler("/ping", mocks.PingHandler().WithAuthMiddleware())
		defer server.Close()

		initialRequest := mocks.PrepareInitialRequestBody(t.Context(), clientWallet)

		serverWallet.OnGetPublicKeyOnce(prepareExampleIdentityKey(t), nil)
		serverWallet.OnCreateHmacOnce(&wallet.CreateHmacResult{
			Hmac: []byte("mockhmacsignature"),
		}, nil)
		serverWallet.OnCreateNonceOnce(mocks.DefaultNonces[0], nil)
		serverWallet.OnCreateSignatureOnce(prepareExampleSignature(t), nil)

		response, err := server.SendNonGeneralRequest(t, initialRequest.AuthMessage())
		require.NoError(t, err)
		testutils.ResponseOK(t, response)

		authMessage, err := mocks.MapBodyToAuthMessage(t, response)
		require.NoError(t, err)
		// when
		pingPath := server.URL() + "/ping"
		request, err := http.NewRequest(http.MethodGet, pingPath, nil)
		require.NoError(t, err)
		err = mocks.PrepareGeneralRequestHeaders(t.Context(), clientWallet, authMessage, request)
		require.NoError(t, err)
		serverWallet.OnVerifyNonceOnce(true, nil)
		serverWallet.OnVerifySignatureOnce(&wallet.VerifySignatureResult{Valid: false}, nil)
		sessionManager.OnGetSessionOnce("02ba6965682077505d33a05e2206007e4795c045faa439fc3629d05dfb50c0bcb1", &auth.PeerSession{
			IsAuthenticated: false,
			SessionNonce:    authMessage.InitialNonce,
			PeerNonce:       authMessage.YourNonce,
			PeerIdentityKey: initialRequest.IdentityKey,
			LastUpdate:      1747241090788,
		})
		response, err = server.SendGeneralRequest(t, request)

		// then
		require.NoError(t, err)
		testutils.NotAuthorized(t, response)
		require.Contains(t, testutils.ReadBodyForTest(t, response), "authentication failed")

	})
}

func TestAuthMiddleware_GeneralRequest_HeaderValidation(t *testing.T) {
	// given
	// sessionManager := mocks.NewMockableSessionManager()
	// serverWallet := mocks.NewMockableWallet()
	// server := mocks.CreateMockHTTPServer(serverWallet, sessionManager, mocks.WithLogger).
	// 	WithHandler("/", mocks.IndexHandler().WithAuthMiddleware()).
	// 	WithHandler("/ping", mocks.PingHandler().WithAuthMiddleware())
	// defer server.Close()

	// clientWallet := mocks.CreateClientMockWallet()
	// authMessage := prepareInitialRequest(t, serverWallet, clientWallet, server)

	// pingPath := server.URL() + "/ping"

	t.Run("no version header", func(t *testing.T) {
		// given
		sessionManager := mocks.NewMockableSessionManager()
		serverWallet := mocks.NewMockableWallet()
		clientWallet := mocks.CreateClientMockWallet()
		server := mocks.CreateMockHTTPServer(serverWallet, sessionManager, mocks.WithLogger).
			WithHandler("/", mocks.IndexHandler().WithAuthMiddleware()).
			WithHandler("/ping", mocks.PingHandler().WithAuthMiddleware())
		defer server.Close()

		initialRequest := mocks.PrepareInitialRequestBody(t.Context(), clientWallet)

		serverWallet.OnGetPublicKeyOnce(prepareExampleIdentityKey(t), nil)
		serverWallet.OnCreateHmacOnce(&wallet.CreateHmacResult{
			Hmac: []byte("mockhmacsignature"),
		}, nil)
		serverWallet.OnCreateNonceOnce(mocks.DefaultNonces[0], nil)
		serverWallet.OnCreateSignatureOnce(prepareExampleSignature(t), nil)

		response, err := server.SendNonGeneralRequest(t, initialRequest.AuthMessage())
		require.NoError(t, err)
		testutils.ResponseOK(t, response)

		authMessage, err := mocks.MapBodyToAuthMessage(t, response)
		require.NoError(t, err)

		// when
		pingPath := server.URL() + "/ping"
		request, err := http.NewRequest(http.MethodGet, pingPath, nil)
		require.NoError(t, err)
		err = mocks.PrepareGeneralRequestHeaders(t.Context(), clientWallet, authMessage, request)
		request.Header.Del(constants.HeaderVersion)

		require.NoError(t, err)
		serverWallet.OnVerifyNonceOnce(true, nil)
		serverWallet.OnVerifySignatureOnce(&wallet.VerifySignatureResult{Valid: false}, nil)
		sessionManager.OnGetSessionOnce("02ba6965682077505d33a05e2206007e4795c045faa439fc3629d05dfb50c0bcb1", &auth.PeerSession{
			IsAuthenticated: false,
			SessionNonce:    authMessage.InitialNonce,
			PeerNonce:       authMessage.YourNonce,
			PeerIdentityKey: initialRequest.IdentityKey,
			LastUpdate:      1747241090788,
		})
		response, err = server.SendGeneralRequest(t, request)

		// then
		require.NoError(t, err)
		testutils.NotAuthorized(t, response)
		require.Contains(t, testutils.ReadBodyForTest(t, response), "authentication required")
	})

	t.Run("no identity key", func(t *testing.T) {
		// given
		sessionManager := mocks.NewMockableSessionManager()
		serverWallet := mocks.NewMockableWallet()
		clientWallet := mocks.CreateClientMockWallet()
		server := mocks.CreateMockHTTPServer(serverWallet, sessionManager, mocks.WithLogger).
			WithHandler("/", mocks.IndexHandler().WithAuthMiddleware()).
			WithHandler("/ping", mocks.PingHandler().WithAuthMiddleware())
		defer server.Close()

		initialRequest := mocks.PrepareInitialRequestBody(t.Context(), clientWallet)

		serverWallet.OnGetPublicKeyOnce(prepareExampleIdentityKey(t), nil)
		serverWallet.OnCreateHmacOnce(&wallet.CreateHmacResult{
			Hmac: []byte("mockhmacsignature"),
		}, nil)
		serverWallet.OnCreateNonceOnce(mocks.DefaultNonces[0], nil)
		serverWallet.OnCreateSignatureOnce(prepareExampleSignature(t), nil)

		response, err := server.SendNonGeneralRequest(t, initialRequest.AuthMessage())
		require.NoError(t, err)
		testutils.ResponseOK(t, response)

		authMessage, err := mocks.MapBodyToAuthMessage(t, response)
		require.NoError(t, err)

		// when
		pingPath := server.URL() + "/ping"
		request, err := http.NewRequest(http.MethodGet, pingPath, nil)
		require.NoError(t, err)
		err = mocks.PrepareGeneralRequestHeaders(t.Context(), clientWallet, authMessage, request)
		request.Header.Del(constants.HeaderIdentityKey)

		require.NoError(t, err)
		serverWallet.OnVerifyNonceOnce(true, nil)
		serverWallet.OnVerifySignatureOnce(&wallet.VerifySignatureResult{Valid: false}, nil)
		sessionManager.OnGetSessionOnce("02ba6965682077505d33a05e2206007e4795c045faa439fc3629d05dfb50c0bcb1", &auth.PeerSession{
			IsAuthenticated: false,
			SessionNonce:    authMessage.InitialNonce,
			PeerNonce:       authMessage.YourNonce,
			PeerIdentityKey: initialRequest.IdentityKey,
			LastUpdate:      1747241090788,
		})
		response, err = server.SendGeneralRequest(t, request)

		// then
		require.NoError(t, err)
		testutils.BadRequest(t, response)
		testutils.MissingHeaderError(t, response, "identity key")
	})

	t.Run("no nonce", func(t *testing.T) {
		// given
		sessionManager := mocks.NewMockableSessionManager()
		serverWallet := mocks.NewMockableWallet()
		clientWallet := mocks.CreateClientMockWallet()
		server := mocks.CreateMockHTTPServer(serverWallet, sessionManager, mocks.WithLogger).
			WithHandler("/", mocks.IndexHandler().WithAuthMiddleware()).
			WithHandler("/ping", mocks.PingHandler().WithAuthMiddleware())
		defer server.Close()

		initialRequest := mocks.PrepareInitialRequestBody(t.Context(), clientWallet)

		serverWallet.OnGetPublicKeyOnce(prepareExampleIdentityKey(t), nil)
		serverWallet.OnCreateHmacOnce(&wallet.CreateHmacResult{
			Hmac: []byte("mockhmacsignature"),
		}, nil)
		serverWallet.OnCreateNonceOnce(mocks.DefaultNonces[0], nil)
		serverWallet.OnCreateSignatureOnce(prepareExampleSignature(t), nil)

		response, err := server.SendNonGeneralRequest(t, initialRequest.AuthMessage())
		require.NoError(t, err)
		testutils.ResponseOK(t, response)

		authMessage, err := mocks.MapBodyToAuthMessage(t, response)
		require.NoError(t, err)

		// when
		pingPath := server.URL() + "/ping"
		request, err := http.NewRequest(http.MethodGet, pingPath, nil)
		require.NoError(t, err)
		err = mocks.PrepareGeneralRequestHeaders(t.Context(), clientWallet, authMessage, request)
		request.Header.Del(constants.HeaderNonce)

		require.NoError(t, err)
		serverWallet.OnVerifyNonceOnce(true, nil)
		serverWallet.OnVerifySignatureOnce(&wallet.VerifySignatureResult{Valid: false}, nil)
		sessionManager.OnGetSessionOnce("02ba6965682077505d33a05e2206007e4795c045faa439fc3629d05dfb50c0bcb1", &auth.PeerSession{
			IsAuthenticated: false,
			SessionNonce:    authMessage.InitialNonce,
			PeerNonce:       authMessage.YourNonce,
			PeerIdentityKey: initialRequest.IdentityKey,
			LastUpdate:      1747241090788,
		})
		response, err = server.SendGeneralRequest(t, request)

		// then
		require.NoError(t, err)
		testutils.NotAuthorized(t, response)
		require.Contains(t, testutils.ReadBodyForTest(t, response), "authentication failed")
	})

	t.Run("no your nonce", func(t *testing.T) {
		// given
		sessionManager := mocks.NewMockableSessionManager()
		serverWallet := mocks.NewMockableWallet()
		clientWallet := mocks.CreateClientMockWallet()
		server := mocks.CreateMockHTTPServer(serverWallet, sessionManager, mocks.WithLogger).
			WithHandler("/", mocks.IndexHandler().WithAuthMiddleware()).
			WithHandler("/ping", mocks.PingHandler().WithAuthMiddleware())
		defer server.Close()

		initialRequest := mocks.PrepareInitialRequestBody(t.Context(), clientWallet)

		serverWallet.OnGetPublicKeyOnce(prepareExampleIdentityKey(t), nil)
		serverWallet.OnCreateHmacOnce(&wallet.CreateHmacResult{
			Hmac: []byte("mockhmacsignature"),
		}, nil)
		serverWallet.OnCreateNonceOnce(mocks.DefaultNonces[0], nil)
		serverWallet.OnCreateSignatureOnce(prepareExampleSignature(t), nil)

		response, err := server.SendNonGeneralRequest(t, initialRequest.AuthMessage())
		require.NoError(t, err)
		testutils.ResponseOK(t, response)

		authMessage, err := mocks.MapBodyToAuthMessage(t, response)
		require.NoError(t, err)

		// when
		pingPath := server.URL() + "/ping"
		request, err := http.NewRequest(http.MethodGet, pingPath, nil)
		require.NoError(t, err)
		err = mocks.PrepareGeneralRequestHeaders(t.Context(), clientWallet, authMessage, request)
		request.Header.Del(constants.HeaderYourNonce)

		require.NoError(t, err)
		serverWallet.OnVerifyNonceOnce(true, nil)
		serverWallet.OnVerifySignatureOnce(&wallet.VerifySignatureResult{Valid: false}, nil)
		sessionManager.OnGetSessionOnce("02ba6965682077505d33a05e2206007e4795c045faa439fc3629d05dfb50c0bcb1", &auth.PeerSession{
			IsAuthenticated: false,
			SessionNonce:    authMessage.InitialNonce,
			PeerNonce:       authMessage.YourNonce,
			PeerIdentityKey: initialRequest.IdentityKey,
			LastUpdate:      1747241090788,
		})
		response, err = server.SendGeneralRequest(t, request)

		// then
		require.NoError(t, err)
		testutils.NotAuthorized(t, response)
		require.Contains(t, testutils.ReadBodyForTest(t, response), "authentication failed")
	})

	t.Run("no signature", func(t *testing.T) {
		// given
		sessionManager := mocks.NewMockableSessionManager()
		serverWallet := mocks.NewMockableWallet()
		clientWallet := mocks.CreateClientMockWallet()
		server := mocks.CreateMockHTTPServer(serverWallet, sessionManager, mocks.WithLogger).
			WithHandler("/", mocks.IndexHandler().WithAuthMiddleware()).
			WithHandler("/ping", mocks.PingHandler().WithAuthMiddleware())
		defer server.Close()

		initialRequest := mocks.PrepareInitialRequestBody(t.Context(), clientWallet)

		serverWallet.OnGetPublicKeyOnce(prepareExampleIdentityKey(t), nil)
		serverWallet.OnCreateHmacOnce(&wallet.CreateHmacResult{
			Hmac: []byte("mockhmacsignature"),
		}, nil)
		serverWallet.OnCreateNonceOnce(mocks.DefaultNonces[0], nil)
		serverWallet.OnCreateSignatureOnce(prepareExampleSignature(t), nil)

		response, err := server.SendNonGeneralRequest(t, initialRequest.AuthMessage())
		require.NoError(t, err)
		testutils.ResponseOK(t, response)

		authMessage, err := mocks.MapBodyToAuthMessage(t, response)
		require.NoError(t, err)

		// when
		pingPath := server.URL() + "/ping"
		request, err := http.NewRequest(http.MethodGet, pingPath, nil)
		require.NoError(t, err)
		err = mocks.PrepareGeneralRequestHeaders(t.Context(), clientWallet, authMessage, request)
		request.Header.Del(constants.HeaderSignature)

		require.NoError(t, err)
		serverWallet.OnVerifyNonceOnce(true, nil)
		serverWallet.OnVerifySignatureOnce(&wallet.VerifySignatureResult{Valid: false}, nil)
		sessionManager.OnGetSessionOnce("02ba6965682077505d33a05e2206007e4795c045faa439fc3629d05dfb50c0bcb1", &auth.PeerSession{
			IsAuthenticated: false,
			SessionNonce:    authMessage.InitialNonce,
			PeerNonce:       authMessage.YourNonce,
			PeerIdentityKey: initialRequest.IdentityKey,
			LastUpdate:      1747241090788,
		})
		response, err = server.SendGeneralRequest(t, request)

		// then
		require.NoError(t, err)
		testutils.NotAuthorized(t, response)
		require.Contains(t, testutils.ReadBodyForTest(t, response), "authentication failed")
	})

	t.Run("wrong signature format", func(t *testing.T) {
		// given
		sessionManager := mocks.NewMockableSessionManager()
		serverWallet := mocks.NewMockableWallet()
		clientWallet := mocks.CreateClientMockWallet()
		server := mocks.CreateMockHTTPServer(serverWallet, sessionManager, mocks.WithLogger).
			WithHandler("/", mocks.IndexHandler().WithAuthMiddleware()).
			WithHandler("/ping", mocks.PingHandler().WithAuthMiddleware())
		defer server.Close()

		initialRequest := mocks.PrepareInitialRequestBody(t.Context(), clientWallet)

		serverWallet.OnGetPublicKeyOnce(prepareExampleIdentityKey(t), nil)
		serverWallet.OnCreateHmacOnce(&wallet.CreateHmacResult{
			Hmac: []byte("mockhmacsignature"),
		}, nil)
		serverWallet.OnCreateNonceOnce(mocks.DefaultNonces[0], nil)
		serverWallet.OnCreateSignatureOnce(prepareExampleSignature(t), nil)

		response, err := server.SendNonGeneralRequest(t, initialRequest.AuthMessage())
		require.NoError(t, err)
		testutils.ResponseOK(t, response)

		authMessage, err := mocks.MapBodyToAuthMessage(t, response)
		require.NoError(t, err)

		// when
		pingPath := server.URL() + "/ping"
		request, err := http.NewRequest(http.MethodGet, pingPath, nil)
		require.NoError(t, err)
		err = mocks.PrepareGeneralRequestHeaders(t.Context(), clientWallet, authMessage, request, mocks.WithWrongSignature)

		require.NoError(t, err)
		serverWallet.OnVerifyNonceOnce(true, nil)
		serverWallet.OnVerifySignatureOnce(&wallet.VerifySignatureResult{Valid: false}, nil)
		sessionManager.OnGetSessionOnce("02ba6965682077505d33a05e2206007e4795c045faa439fc3629d05dfb50c0bcb1", &auth.PeerSession{
			IsAuthenticated: false,
			SessionNonce:    authMessage.InitialNonce,
			PeerNonce:       authMessage.YourNonce,
			PeerIdentityKey: initialRequest.IdentityKey,
			LastUpdate:      1747241090788,
		})
		response, err = server.SendGeneralRequest(t, request)

		// then
		require.NoError(t, err)
		testutils.BadRequest(t, response)
		require.Contains(t, testutils.ReadBodyForTest(t, response), "invalid signature format")
	})

	t.Run("wrong nonce format", func(t *testing.T) {
		// given
		sessionManager := mocks.NewMockableSessionManager()
		serverWallet := mocks.NewMockableWallet()
		clientWallet := mocks.CreateClientMockWallet()
		server := mocks.CreateMockHTTPServer(serverWallet, sessionManager, mocks.WithLogger).
			WithHandler("/", mocks.IndexHandler().WithAuthMiddleware()).
			WithHandler("/ping", mocks.PingHandler().WithAuthMiddleware())
		defer server.Close()

		initialRequest := mocks.PrepareInitialRequestBody(t.Context(), clientWallet)

		serverWallet.OnGetPublicKeyOnce(prepareExampleIdentityKey(t), nil)
		serverWallet.OnCreateHmacOnce(&wallet.CreateHmacResult{
			Hmac: []byte("mockhmacsignature"),
		}, nil)
		serverWallet.OnCreateNonceOnce(mocks.DefaultNonces[0], nil)
		serverWallet.OnCreateSignatureOnce(prepareExampleSignature(t), nil)

		response, err := server.SendNonGeneralRequest(t, initialRequest.AuthMessage())
		require.NoError(t, err)
		testutils.ResponseOK(t, response)

		authMessage, err := mocks.MapBodyToAuthMessage(t, response)
		require.NoError(t, err)

		// when
		pingPath := server.URL() + "/ping"
		request, err := http.NewRequest(http.MethodGet, pingPath, nil)
		require.NoError(t, err)
		err = mocks.PrepareGeneralRequestHeaders(t.Context(), clientWallet, authMessage, request, mocks.WithWrongNonce)

		require.NoError(t, err)
		serverWallet.OnVerifyNonceOnce(true, nil)
		serverWallet.OnVerifySignatureOnce(&wallet.VerifySignatureResult{Valid: false}, nil)
		sessionManager.OnGetSessionOnce("02ba6965682077505d33a05e2206007e4795c045faa439fc3629d05dfb50c0bcb1", &auth.PeerSession{
			IsAuthenticated: false,
			SessionNonce:    authMessage.InitialNonce,
			PeerNonce:       authMessage.YourNonce,
			PeerIdentityKey: initialRequest.IdentityKey,
			LastUpdate:      1747241090788,
		})
		response, err = server.SendGeneralRequest(t, request)

		// then
		require.NoError(t, err)
		testutils.NotAuthorized(t, response)
		require.Contains(t, testutils.ReadBodyForTest(t, response), "authentication failed")
	})

	t.Run("wrong your nonce format", func(t *testing.T) {
		// given
		sessionManager := mocks.NewMockableSessionManager()
		serverWallet := mocks.NewMockableWallet()
		clientWallet := mocks.CreateClientMockWallet()
		server := mocks.CreateMockHTTPServer(serverWallet, sessionManager, mocks.WithLogger).
			WithHandler("/", mocks.IndexHandler().WithAuthMiddleware()).
			WithHandler("/ping", mocks.PingHandler().WithAuthMiddleware())
		defer server.Close()

		initialRequest := mocks.PrepareInitialRequestBody(t.Context(), clientWallet)

		serverWallet.OnGetPublicKeyOnce(prepareExampleIdentityKey(t), nil)
		serverWallet.OnCreateHmacOnce(&wallet.CreateHmacResult{
			Hmac: []byte("mockhmacsignature"),
		}, nil)
		serverWallet.OnCreateNonceOnce(mocks.DefaultNonces[0], nil)
		serverWallet.OnCreateSignatureOnce(prepareExampleSignature(t), nil)

		response, err := server.SendNonGeneralRequest(t, initialRequest.AuthMessage())
		require.NoError(t, err)
		testutils.ResponseOK(t, response)

		authMessage, err := mocks.MapBodyToAuthMessage(t, response)
		require.NoError(t, err)

		// when
		pingPath := server.URL() + "/ping"
		request, err := http.NewRequest(http.MethodGet, pingPath, nil)
		require.NoError(t, err)
		err = mocks.PrepareGeneralRequestHeaders(t.Context(), clientWallet, authMessage, request, mocks.WithWrongYourNonce)

		require.NoError(t, err)
		serverWallet.OnVerifyNonceOnce(true, nil)
		serverWallet.OnVerifySignatureOnce(&wallet.VerifySignatureResult{Valid: false}, nil)
		sessionManager.OnGetSessionOnce("02ba6965682077505d33a05e2206007e4795c045faa439fc3629d05dfb50c0bcb1", &auth.PeerSession{
			IsAuthenticated: false,
			SessionNonce:    authMessage.InitialNonce,
			PeerNonce:       authMessage.YourNonce,
			PeerIdentityKey: initialRequest.IdentityKey,
			LastUpdate:      1747241090788,
		})
		response, err = server.SendGeneralRequest(t, request)

		// then
		require.NoError(t, err)
		testutils.NotAuthorized(t, response)
		require.Contains(t, testutils.ReadBodyForTest(t, response), "authentication failed")
	})

	t.Run("wrong version format", func(t *testing.T) {
		// given
		sessionManager := mocks.NewMockableSessionManager()
		serverWallet := mocks.NewMockableWallet()
		clientWallet := mocks.CreateClientMockWallet()
		server := mocks.CreateMockHTTPServer(serverWallet, sessionManager, mocks.WithLogger).
			WithHandler("/", mocks.IndexHandler().WithAuthMiddleware()).
			WithHandler("/ping", mocks.PingHandler().WithAuthMiddleware())
		defer server.Close()

		initialRequest := mocks.PrepareInitialRequestBody(t.Context(), clientWallet)

		serverWallet.OnGetPublicKeyOnce(prepareExampleIdentityKey(t), nil)
		serverWallet.OnCreateHmacOnce(&wallet.CreateHmacResult{
			Hmac: []byte("mockhmacsignature"),
		}, nil)
		serverWallet.OnCreateNonceOnce(mocks.DefaultNonces[0], nil)
		serverWallet.OnCreateSignatureOnce(prepareExampleSignature(t), nil)

		response, err := server.SendNonGeneralRequest(t, initialRequest.AuthMessage())
		require.NoError(t, err)
		testutils.ResponseOK(t, response)

		authMessage, err := mocks.MapBodyToAuthMessage(t, response)
		require.NoError(t, err)

		// when
		pingPath := server.URL() + "/ping"
		request, err := http.NewRequest(http.MethodGet, pingPath, nil)
		require.NoError(t, err)
		err = mocks.PrepareGeneralRequestHeaders(t.Context(), clientWallet, authMessage, request, mocks.WithWrongVersion)

		require.NoError(t, err)
		serverWallet.OnVerifyNonceOnce(true, nil)
		serverWallet.OnVerifySignatureOnce(&wallet.VerifySignatureResult{Valid: false}, nil)
		sessionManager.OnGetSessionOnce("02ba6965682077505d33a05e2206007e4795c045faa439fc3629d05dfb50c0bcb1", &auth.PeerSession{
			IsAuthenticated: false,
			SessionNonce:    authMessage.InitialNonce,
			PeerNonce:       authMessage.YourNonce,
			PeerIdentityKey: initialRequest.IdentityKey,
			LastUpdate:      1747241090788,
		})
		response, err = server.SendGeneralRequest(t, request)

		// then
		require.NoError(t, err)
		testutils.InternalServerError(t, response)
	})
}
