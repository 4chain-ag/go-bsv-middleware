package mocks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/4chain-ag/go-bsv-middleware/pkg/middleware/auth"
	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/sessionmanager"
	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
	"github.com/4chain-ag/go-bsv-middleware/pkg/transport"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/stretchr/testify/require"
)

// MockHTTPServer is a mock HTTP server used in tests
type MockHTTPServer struct {
	mux                     *http.ServeMux
	server                  *httptest.Server
	allowUnauthenticated    bool
	logger                  *slog.Logger
	authMiddleware          *auth.Middleware
	certificateRequirements *transport.RequestedCertificateSet
	onCertificatesReceived  transport.OnCertificatesReceivedFunc
}

// MockHTTPHandler is a mock HTTP handler used in tests
type MockHTTPHandler struct {
	useAuthMiddleware    bool
	usePaymentMiddleware bool
	h                    http.Handler
}

// CreateMockHTTPServer creates a new mock HTTP server
func CreateMockHTTPServer(
	wallet wallet.WalletInterface,
	sessionManager sessionmanager.SessionManagerInterface,
	opts ...func(s *MockHTTPServer) *MockHTTPServer) *MockHTTPServer {

	mux := http.NewServeMux()
	mockServer := &MockHTTPServer{mux: mux}

	for _, opt := range opts {
		opt(mockServer)
	}

	mockServer.createMiddleware(wallet, sessionManager)

	s := httptest.NewServer(mux)
	mockServer.server = s

	return mockServer
}

// WithHandler adds a custom handler to the server
func (s *MockHTTPServer) WithHandler(path string, handler *MockHTTPHandler) *MockHTTPServer {
	// TODO: uncomment when payment middleware implemented
	//if handler.usePaymentMiddleware {
	//	handler.h = s.paymentMiddleware.Handler(handler.h)
	//}

	if handler.useAuthMiddleware {
		handler.h = s.authMiddleware.Handler(handler.h)
	}

	s.mux.Handle(path, handler.h)

	return s
}

// Close closes the server
func (s *MockHTTPServer) Close() {
	s.server.Close()
}

// URL returns the server URL
func (s *MockHTTPServer) URL() string {
	return s.server.URL
}

// SendNonGeneralRequest sends a non-general request to the server
func (s *MockHTTPServer) SendNonGeneralRequest(t *testing.T, msg *transport.AuthMessage) (*http.Response, error) {
	authURL := s.URL() + "/.well-known/auth"
	authMethod := "POST"

	dataBytes, err := json.Marshal(msg)
	require.Nil(t, err)

	response := prepareAndCallRequest(t, authMethod, authURL, nil, dataBytes)

	return response, nil
}

// SendGeneralRequest sends a general request to the server
func (s *MockHTTPServer) SendGeneralRequest(t *testing.T, request *http.Request) (*http.Response, error) {
	client := &http.Client{}
	response, err := client.Do(request)
	require.Nil(t, err)

	return response, nil
}

// SendCertificateResponse sends a certificate response to the server
func (s *MockHTTPServer) SendCertificateResponse(t *testing.T, clientWallet wallet.WalletInterface, certificates *[]wallet.VerifiableCertificate) (*http.Response, error) {
	initialRequest := PrepareInitialRequestBody(clientWallet)
	response, err := s.SendNonGeneralRequest(t, initialRequest.AuthMessage())
	require.NoError(t, err)

	authMessage, err := MapBodyToAuthMessage(t, response)
	require.NoError(t, err)

	nonce, err := clientWallet.CreateNonce(context.Background())
	require.NoError(t, err)

	identityKey, err := clientWallet.GetPublicKey(&wallet.GetPublicKeyArgs{IdentityKey: true}, "")
	require.NoError(t, err)

	certMessage := transport.AuthMessage{
		Version:      "0.1",
		MessageType:  transport.CertificateResponse,
		IdentityKey:  identityKey.PublicKey.ToDERHex(),
		Nonce:        &nonce,
		YourNonce:    &authMessage.InitialNonce,
		Certificates: certificates,
	}

	certBytes, err := json.Marshal(*certificates)
	require.NoError(t, err)

	serverKey, err := ec.PublicKeyFromString(authMessage.IdentityKey)
	require.NoError(t, err)

	signatureArgs := &wallet.CreateSignatureArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID: wallet.DefaultAuthProtocol,
			KeyID:      fmt.Sprintf("%s %s", nonce, authMessage.InitialNonce),
			Counterparty: wallet.Counterparty{
				Type:         wallet.CounterpartyTypeOther,
				Counterparty: serverKey,
			},
		},
		Data: certBytes,
	}

	signatureResult, err := clientWallet.CreateSignature(signatureArgs, "")
	require.NoError(t, err)

	signBytes := signatureResult.Signature.Serialize()
	certMessage.Signature = &signBytes

	jsonData, err := json.Marshal(certMessage)
	require.NoError(t, err)

	req, err := http.NewRequest("POST", s.URL()+"/.well-known/auth", bytes.NewBuffer(jsonData))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)

	return resp, nil
}

func (s *MockHTTPServer) createMiddleware(wallet wallet.WalletInterface, sessionManager sessionmanager.SessionManagerInterface) {
	if s.logger == nil {
		s.logger = slog.New(slog.DiscardHandler)
	}

	opts := auth.Config{
		AllowUnauthenticated:   s.allowUnauthenticated,
		Logger:                 s.logger,
		Wallet:                 wallet,
		CertificatesToRequest:  s.certificateRequirements,
		OnCertificatesReceived: s.onCertificatesReceived,
		SessionManager:         sessionManager,
	}

	var err error
	s.authMiddleware, err = auth.New(opts)
	if err != nil {
		panic("failed to create auth middleware")
	}
}

// WithAuthMiddleware adds auth middleware to the server
func (h *MockHTTPHandler) WithAuthMiddleware() *MockHTTPHandler {
	h.useAuthMiddleware = true
	return h
}

// WithPaymentMiddleware adds payment middleware to the server
func (h *MockHTTPHandler) WithPaymentMiddleware() *MockHTTPHandler {
	h.usePaymentMiddleware = true
	return h
}

// IndexHandler is a mock HTTP handler for the index route
func IndexHandler() *MockHTTPHandler {
	return &MockHTTPHandler{
		h: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	}
}

// PingHandler is a mock HTTP handler for the ping route
func PingHandler() *MockHTTPHandler {
	return &MockHTTPHandler{
		h: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte("Pong!")); err != nil {
				fmt.Println("Failed to write response")
			}
		}),
	}
}

// WithAllowUnauthenticated is a MockHTTPServer optional setting which sets allowUnauthenticated flag to true
func WithAllowUnauthenticated(s *MockHTTPServer) *MockHTTPServer {
	s.allowUnauthenticated = true
	return s
}

// WithLogger is a MockHTTPServer optional setting which  sets up logger for the server
func WithLogger(s *MockHTTPServer) *MockHTTPServer {
	logHandler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})
	s.logger = slog.New(logHandler)
	return s
}

func prepareAndCallRequest(t *testing.T, method, authURL string, headers map[string]string, jsonData []byte) *http.Response {
	req, err := http.NewRequest(method, authURL, bytes.NewBuffer(jsonData))
	require.Nil(t, err)

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	client := &http.Client{}
	response, err := client.Do(req)
	require.Nil(t, err)

	return response
}

// MapBodyToAuthMessage maps the response body to an AuthMessage
func MapBodyToAuthMessage(t *testing.T, response *http.Response) (*transport.AuthMessage, error) {
	defer func() {
		err := response.Body.Close()
		require.NoError(t, err)
	}()

	body, err := io.ReadAll(response.Body)
	require.Nil(t, err)

	var authMessage *transport.AuthMessage
	if err = json.Unmarshal(body, &authMessage); err != nil {
		return nil, errors.New("failed to unmarshal response")
	}

	return authMessage, nil
}

// WithCertificateRequirements is a MockHTTPServer optional setting that adds certificate requirements
func WithCertificateRequirements(reqs *transport.RequestedCertificateSet, onReceived transport.OnCertificatesReceivedFunc) func(s *MockHTTPServer) *MockHTTPServer {
	return func(s *MockHTTPServer) *MockHTTPServer {
		s.certificateRequirements = reqs
		s.onCertificatesReceived = onReceived
		return s
	}
}
