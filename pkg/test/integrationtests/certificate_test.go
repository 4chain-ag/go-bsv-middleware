package integrationtests

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/4chain-ag/go-bsv-middleware/pkg/middleware/auth"
	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
	walletFixtures "github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet/test"
	"github.com/4chain-ag/go-bsv-middleware/pkg/transport"
	"github.com/stretchr/testify/require"
)

const address = "http://localhost"

// TestAuthMiddleware_CertificateAuthentication_HappyPath tests the certificate authentication flow
func TestAuthMiddleware_CertificateAuthentication_HappyPath(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)

	trustedCertifier := "02certifieridentitykey00000000000000000000000000000000000000000000000"
	certificateToRequest := transport.RequestedCertificateSet{
		Certifiers: []string{trustedCertifier},
		Types: map[string][]string{
			"age-verification": {"age-verification"},
		},
	}

	opts := auth.Options{
		AllowUnauthenticated:  false,
		Logger:                logger,
		Wallet:                wallet.NewMockWallet(true, &walletFixtures.ServerIdentityKey, walletFixtures.DefaultNonces[0]),
		CertificatesToRequest: &certificateToRequest,
	}
	middleware := auth.New(opts)

	mux := http.NewServeMux()

	mux.Handle("/", middleware.Handler(http.HandlerFunc(pingHandler)))
	mux.Handle("/protected", middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "Protected content accessed successfully")
	})))

	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	serverAddr := fmt.Sprintf("%s%s", address, server.Addr)

	go func() {
		logger.Info("Server started", slog.String("addr", server.Addr))
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("Server failed", slog.Any("error", err))
		}
	}()
	time.Sleep(1 * time.Second)

	clientWallet := wallet.NewMockWallet(true, &walletFixtures.ClientIdentityKey, walletFixtures.DefaultNonces[0]) // walletFixtures.ClientNonces...)

	t.Log("Step 1: Performing initial handshake")
	authResponse := performInitialHandshake(t, serverAddr, clientWallet)
	require.NotNil(t, authResponse, "Initial handshake should succeed")

	t.Log("Step 2: Attempting to access protected content without certificate")
	resp, _ := accessProtectedContent(t, serverAddr, clientWallet, authResponse)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode, "Should receive a 401 Status Unauthorized")

	t.Log("Step 3: Sending certificate")
	sendCertificate(t, serverAddr, clientWallet, authResponse, trustedCertifier)

	t.Log("Step 4: Attempting to access protected content with certificate")
	resp, _ = accessProtectedContent(t, serverAddr, clientWallet, authResponse)
	require.Equal(t, http.StatusOK, resp.StatusCode, "Should receive a 200 OK")
}

func performInitialHandshake(t *testing.T, serverURL string, clientWallet wallet.WalletInterface) *transport.AuthMessage {
	initialNonce := walletFixtures.DefaultNonces[0]

	identityKey, err := clientWallet.GetPublicKey(context.Background(), wallet.GetPublicKeyOptions{IdentityKey: true})
	require.NoError(t, err, "Should be able to get identity key")

	initialRequest := transport.AuthMessage{
		Version:      "0.1",
		MessageType:  "initialRequest",
		IdentityKey:  identityKey,
		InitialNonce: initialNonce,
	}

	requestBody, err := json.Marshal(initialRequest)
	require.NoError(t, err, "Should be able to marshal request")

	resp, err := http.Post(serverURL+"/.well-known/auth", "application/json", strings.NewReader(string(requestBody)))
	require.NoError(t, err, "Should be able to send request")
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "Should be able to read response")

	var authResponse transport.AuthMessage
	err = json.Unmarshal(respBody, &authResponse)
	require.NoError(t, err, "Should be able to parse response")

	return &authResponse
}

func accessProtectedContent(t *testing.T, serverURL string, clientWallet wallet.WalletInterface, authResponse *transport.AuthMessage) (*http.Response, string) {
	req, err := http.NewRequest("GET", serverURL+"/protected", nil)
	require.NoError(t, err, "Should be able to create request")

	addAuthHeaders(t, req, clientWallet, authResponse)

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err, "Should be able to send request")
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "Should be able to read response")

	return resp, string(respBody)
}

func sendCertificate(t *testing.T, serverURL string, clientWallet wallet.WalletInterface, authResponse *transport.AuthMessage, certifierKey string) {
	identityKey, err := clientWallet.GetPublicKey(context.Background(), wallet.GetPublicKeyOptions{IdentityKey: true})
	require.NoError(t, err, "Should be able to get identity key")

	nonce, err := clientWallet.CreateNonce(context.Background())
	require.NoError(t, err, "Should be able to create nonce")

	certMessage := transport.AuthMessage{
		Version:     "0.1",
		MessageType: "certificateResponse",
		IdentityKey: identityKey,
		Nonce:       &nonce,
		YourNonce:   authResponse.Nonce,
		// TODO: move certificates to body after signing POST request introduction
		Certificate: &wallet.VerifiableCertificate{
			Certificate: wallet.Certificate{
				Type:         "age-verification",
				SerialNumber: "12345",
				Subject:      identityKey,
				Certifier:    certifierKey,
				Fields: map[string]any{
					"age": 21,
				},
				Signature: "mocksignature",
			},
			Keyring:         map[string]string{"certifier": certifierKey},
			DecryptedFields: nil,
		},
	}

	requestBody, err := json.Marshal(certMessage)
	require.NoError(t, err, "Should be able to marshal certificate message")

	resp, err := http.Post(serverURL+"/.well-known/auth", "application/json", strings.NewReader(string(requestBody)))
	require.NoError(t, err, "Should be able to send certificate")
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode, "Certificate submission should succeed")
}

func addAuthHeaders(t *testing.T, req *http.Request, clientWallet wallet.WalletInterface, authResponse *transport.AuthMessage) {

	serverIdentityKey := authResponse.IdentityKey
	serverNonce := authResponse.InitialNonce

	identityKey, err := clientWallet.GetPublicKey(context.Background(), wallet.GetPublicKeyOptions{IdentityKey: true})
	require.NoError(t, err, "Should be able to get identity key")

	requestID := generateRandom()

	newNonce, err := clientWallet.CreateNonce(context.Background())
	if err != nil {
		panic(err)
	}

	var writer bytes.Buffer

	writer.Write(requestID)

	writeVarIntNum(&writer, int64(len(req.Method)))
	writer.Write([]byte(req.Method))

	writeVarIntNum(&writer, int64(len(req.URL.Path)))
	writer.Write([]byte(req.URL.Path))

	writeVarIntNum(&writer, -1)

	writeVarIntNum(&writer, 0)

	writeVarIntNum(&writer, -1)

	signature, err := clientWallet.CreateSignature(
		context.Background(),
		writer.Bytes(),
		"auth message signature",
		fmt.Sprintf("%s %s", newNonce, serverNonce),
		serverIdentityKey,
	)
	if err != nil {
		panic(err)
	}

	req.Header.Set("x-bsv-auth-version", "0.1")
	req.Header.Set("x-bsv-auth-identity-key", identityKey)
	req.Header.Set("x-bsv-auth-nonce", newNonce)
	req.Header.Set("x-bsv-auth-your-nonce", *authResponse.YourNonce)
	req.Header.Set("x-bsv-auth-signature", fmt.Sprintf("%x", signature))
	req.Header.Set("x-bsv-auth-request-id", fmt.Sprintf("%x", requestID))
}

func writeVarIntNum(buf *bytes.Buffer, value int64) {
	if value < 0 {
		binary.Write(buf, binary.LittleEndian, int8(-1))
	} else {
		binary.Write(buf, binary.LittleEndian, uint64(value))
	}
}
func generateRandom() []byte {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return b
}

func pingHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Pong!"))
}
