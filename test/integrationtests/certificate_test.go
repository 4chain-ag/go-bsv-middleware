package integrationtests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"testing"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/transport"
	"github.com/bsv-blockchain/go-bsv-middleware/test/assert"
	"github.com/bsv-blockchain/go-bsv-middleware/test/mocks"
	"github.com/bsv-blockchain/go-sdk/auth"
	"github.com/bsv-blockchain/go-sdk/auth/certificates"
	sdkUtils "github.com/bsv-blockchain/go-sdk/auth/utils"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
)

const trustedCertifier = "02certifieridentitykey00000000000000000000000000000000000000000000000"

func TestAuthMiddleware_CertificateHandling(t *testing.T) {
	key, err := ec.PrivateKeyFromHex(mocks.ServerPrivateKeyHex)
	require.NoError(t, err)
	sessionManager := mocks.NewMockableSessionManager()
	serverWallet := mocks.CreateServerMockWallet(key)

	t.Run("initial request with certificate requirements", func(t *testing.T) {
		certificateRequirements := &sdkUtils.RequestedCertificateSet{
			Certifiers: []string{trustedCertifier},
			CertificateTypes: sdkUtils.RequestedCertificateTypeIDAndFieldList{
				"age-verification": []string{"age", "country"},
			},
		}

		onCertificatesReceived := func(senderPublicKey string, certs []*certificates.VerifiableCertificate, req *http.Request, res http.ResponseWriter, next func()) {

			if certs != nil && len(certs) > 0 && next != nil {
				next()
			} else {
				res.Header().Set("Content-Type", "text/plain")
				res.WriteHeader(http.StatusForbidden)
				res.Write([]byte("Invalid certificate"))
			}
		}

		server := mocks.CreateMockHTTPServer(serverWallet, sessionManager, mocks.WithLogger, mocks.WithCertificateRequirements(certificateRequirements, onCertificatesReceived)).
			WithHandler("/", mocks.IndexHandler().WithAuthMiddleware()).
			WithHandler("/ping", mocks.PingHandler().WithAuthMiddleware())
		defer server.Close()

		clientWallet := mocks.CreateClientMockWallet()

		initialRequest := mocks.PrepareInitialRequestBody(t.Context(), clientWallet)
		response, err := server.SendNonGeneralRequest(t, initialRequest.AuthMessage())
		require.NoError(t, err)
		assert.ResponseOK(t, response)
		assert.InitialResponseHeaders(t, response)

		authMessage, err := mocks.MapBodyToAuthMessage(t, response)
		require.NoError(t, err)
		require.NotNil(t, authMessage)

		require.NotNil(t, authMessage.RequestedCertificates, "RequestedCertificates should not be nil")
		require.NotEmpty(t, authMessage.RequestedCertificates.CertificateTypes, "Certificate types should not be empty")
		require.Contains(t, authMessage.RequestedCertificates.CertificateTypes, "age-verification",
			"Certificate types should contain age-verification")
		require.Contains(t, authMessage.RequestedCertificates.Certifiers, trustedCertifier,
			"Certifiers should contain the trusted certifier")
	})

	t.Run("attempt access without certificate", func(t *testing.T) {
		certificateRequirements := &sdkUtils.RequestedCertificateSet{
			Certifiers: []string{trustedCertifier},
			CertificateTypes: sdkUtils.RequestedCertificateTypeIDAndFieldList{
				"age-verification": []string{"age", "country"},
			},
		}

		onCertificatesReceived := func(senderPublicKey string, certs []*certificates.VerifiableCertificate, req *http.Request, res http.ResponseWriter, next func()) {

			if certs != nil && len(certs) > 0 && next != nil {
				next()
			} else {
				res.Header().Set("Content-Type", "text/plain")
				res.WriteHeader(http.StatusForbidden)
				res.Write([]byte("Invalid certificate"))
			}
		}

		server := mocks.CreateMockHTTPServer(serverWallet, sessionManager, mocks.WithLogger, mocks.WithCertificateRequirements(certificateRequirements, onCertificatesReceived)).
			WithHandler("/", mocks.IndexHandler().WithAuthMiddleware()).
			WithHandler("/ping", mocks.PingHandler().WithAuthMiddleware())
		defer server.Close()

		clientWallet := mocks.CreateClientMockWallet()

		initialRequest := mocks.PrepareInitialRequestBody(t.Context(), clientWallet)
		response, err := server.SendNonGeneralRequest(t, initialRequest.AuthMessage())
		require.NoError(t, err)
		authMessage, err := mocks.MapBodyToAuthMessage(t, response)
		require.NoError(t, err)

		request, err := http.NewRequest(http.MethodGet, server.URL()+"/ping", nil)
		require.NoError(t, err)
		err = mocks.PrepareGeneralRequestHeaders(t.Context(), clientWallet, authMessage, request)
		require.NoError(t, err)

		response, err = server.SendGeneralRequest(t, request)
		require.NoError(t, err)
		assert.NotAuthorized(t, response)
	})

	t.Run("send certificate and gain access", func(t *testing.T) {
		sessionManager.Clear()
		certificateRequirements := &sdkUtils.RequestedCertificateSet{
			Certifiers: []string{trustedCertifier},
			CertificateTypes: sdkUtils.RequestedCertificateTypeIDAndFieldList{
				"age-verification": []string{"age", "country"},
			},
		}

		var receivedCertificateFlag bool
		onCertificatesReceived := func(senderPublicKey string, certs []*certificates.VerifiableCertificate, req *http.Request, res http.ResponseWriter, next func()) {
			receivedCertificateFlag = true

			if certs != nil && len(certs) > 0 && next != nil {
				next()
			} else {
				res.Header().Set("Content-Type", "text/plain")
				res.WriteHeader(http.StatusForbidden)
				res.Write([]byte("Invalid certificate"))
			}
		}

		server := mocks.CreateMockHTTPServer(serverWallet, sessionManager, mocks.WithLogger, mocks.WithCertificateRequirements(certificateRequirements, onCertificatesReceived)).
			WithHandler("/", mocks.IndexHandler().WithAuthMiddleware()).
			WithHandler("/ping", mocks.PingHandler().WithAuthMiddleware())
		defer server.Close()

		clientWallet := mocks.CreateClientMockWallet()

		initialRequest := mocks.PrepareInitialRequestBody(t.Context(), clientWallet)
		response, err := server.SendNonGeneralRequest(t, initialRequest.AuthMessage())
		require.NoError(t, err)
		authMessage, err := mocks.MapBodyToAuthMessage(t, response)
		require.NoError(t, err)

		clientIdentityKey, err := clientWallet.GetPublicKey(t.Context(), wallet.GetPublicKeyArgs{IdentityKey: true}, "")
		require.NoError(t, err)

		certifierPubKey, err := ec.PublicKeyFromString(trustedCertifier)
		require.NoError(t, err)

		certificates := []*certificates.VerifiableCertificate{
			{
				Certificate: certificates.Certificate{
					Type:         wallet.Base64String("age-verification"),
					SerialNumber: wallet.Base64String("12345"),
					Subject:      *clientIdentityKey.PublicKey,
					Certifier:    *certifierPubKey,
					Fields: map[wallet.CertificateFieldNameUnder50Bytes]wallet.Base64String{
						"age":     wallet.Base64String("21"),
						"country": wallet.Base64String("Switzerland"),
					},
					Signature: []byte("mocksignature"),
				},
				Keyring: map[wallet.CertificateFieldNameUnder50Bytes]wallet.Base64String{
					"age": wallet.Base64String("mockkey"),
				},
			},
		}

		receivedCertificateFlag = false

		nonce, err := sdkUtils.CreateNonce(t.Context(), clientWallet, wallet.Counterparty{Type: wallet.CounterpartyTypeOther, Counterparty: authMessage.IdentityKey})
		require.NoError(t, err)

		certMessage := auth.AuthMessage{
			Version:      "0.1",
			MessageType:  auth.MessageTypeCertificateResponse,
			IdentityKey:  clientIdentityKey.PublicKey,
			Nonce:        nonce,
			YourNonce:    authMessage.InitialNonce,
			Certificates: certificates,
		}

		certBytes, err := json.Marshal(certificates)
		require.NoError(t, err)

		signatureArgs := wallet.CreateSignatureArgs{
			EncryptionArgs: wallet.EncryptionArgs{
				ProtocolID: transport.DefaultAuthProtocol,
				KeyID:      fmt.Sprintf("%s %s", nonce, authMessage.InitialNonce),
				Counterparty: wallet.Counterparty{
					Type:         wallet.CounterpartyTypeOther,
					Counterparty: authMessage.IdentityKey,
				},
			},
			Data: certBytes,
		}

		signatureResult, err := clientWallet.CreateSignature(t.Context(), signatureArgs, "")
		require.NoError(t, err)

		signBytes := signatureResult.Signature.Serialize()
		certMessage.Signature = signBytes

		jsonData, err := json.Marshal(certMessage)
		require.NoError(t, err)

		req, err := http.NewRequest("POST", server.URL()+"/.well-known/auth", bytes.NewBuffer(jsonData))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{}
		certResponse, err := client.Do(req)
		require.NoError(t, err)
		defer certResponse.Body.Close()

		require.Equal(t, http.StatusOK, certResponse.StatusCode, "Certificate submission should return 200 OK")
		require.True(t, receivedCertificateFlag, "Certificate received callback should be called")

		request, err := http.NewRequest(http.MethodGet, server.URL()+"/ping", nil)
		require.NoError(t, err)
		err = mocks.PrepareGeneralRequestHeaders(t.Context(), clientWallet, authMessage, request)
		require.NoError(t, err)

		response, err = server.SendGeneralRequest(t, request)
		require.NoError(t, err)
		assert.ResponseOK(t, response) // Now should be authorized
	})
}

func TestAuthMiddleware_InvalidCertificateHandling(t *testing.T) {
	// given
	certificateRequirements := &sdkUtils.RequestedCertificateSet{
		Certifiers: []string{trustedCertifier},
		CertificateTypes: sdkUtils.RequestedCertificateTypeIDAndFieldList{
			"age-verification": []string{"age", "country"},
		},
	}

	onCertificatesReceived := func(senderPublicKey string, certs []*certificates.VerifiableCertificate, req *http.Request, res http.ResponseWriter, next func()) {
		if certs == nil || len(certs) == 0 {
			res.Header().Set("Content-Type", "text/plain")
			res.WriteHeader(http.StatusForbidden)
			res.Write([]byte("No valid certificates"))
			return
		}

		cert := (certs)[0]

		if cert.Certificate.Certifier.ToDERHex() != trustedCertifier {
			res.Header().Set("Content-Type", "text/plain")
			res.WriteHeader(http.StatusForbidden)
			res.Write([]byte("Untrusted certifier"))
			return
		}

		if string(cert.Certificate.Type) != "age-verification" {
			res.Header().Set("Content-Type", "text/plain")
			res.WriteHeader(http.StatusForbidden)
			res.Write([]byte("Wrong certificate type"))
			return
		}

		ageValue, ok := cert.Certificate.Fields["age"]
		if !ok {
			res.Header().Set("Content-Type", "text/plain")
			res.WriteHeader(http.StatusForbidden)
			res.Write([]byte("Missing age field"))
			return
		}

		age, err := strconv.Atoi(string(ageValue))
		if err != nil || age < 18 {
			res.Header().Set("Content-Type", "text/plain")
			res.WriteHeader(http.StatusForbidden)
			res.Write([]byte("Invalid age - must be 18+"))
			return
		}

		next()
	}

	sessionManager := mocks.NewMockableSessionManager()
	key, err := ec.PrivateKeyFromHex(mocks.ServerPrivateKeyHex)
	require.NoError(t, err)
	serverWallet := mocks.CreateServerMockWallet(key)
	server := mocks.CreateMockHTTPServer(serverWallet, sessionManager, mocks.WithLogger, mocks.WithCertificateRequirements(certificateRequirements, onCertificatesReceived)).
		WithHandler("/", mocks.IndexHandler().WithAuthMiddleware()).
		WithHandler("/ping", mocks.PingHandler().WithAuthMiddleware())
	defer server.Close()

	clientWallet := mocks.CreateClientMockWallet()
	opts := wallet.GetPublicKeyArgs{IdentityKey: true}
	clientIdentityKey, err := clientWallet.GetPublicKey(t.Context(), opts, "")
	require.NoError(t, err)

	testCases := []struct {
		name           string
		certificates   []*certificates.VerifiableCertificate
		expectedStatus int
	}{
		{
			name: "wrong certifier",
			certificates: func() []*certificates.VerifiableCertificate {
				wrongCertifierKey, err := ec.PublicKeyFromString("wrong-certifier-key")
				if err != nil {
					t.Fatalf("failed to create wrong certifier key: %v", err)
				}
				return []*certificates.VerifiableCertificate{
					{
						Certificate: certificates.Certificate{
							Type:         wallet.Base64String("age-verification"),
							SerialNumber: wallet.Base64String("12345"),
							Subject:      *clientIdentityKey.PublicKey,
							Certifier:    *wrongCertifierKey,
							Fields: map[wallet.CertificateFieldNameUnder50Bytes]wallet.Base64String{
								"age":     wallet.Base64String("21"),
								"country": wallet.Base64String("Switzerland"),
							},
							Signature: []byte("mocksignature"),
						},
						Keyring: map[wallet.CertificateFieldNameUnder50Bytes]wallet.Base64String{},
					},
				}
			}(),
			expectedStatus: http.StatusForbidden,
		},
		{
			name: "wrong certificate type",
			certificates: func() []*certificates.VerifiableCertificate {
				certifierKey, err := ec.PublicKeyFromString(trustedCertifier)
				if err != nil {
					t.Fatalf("failed to create certifier key: %v", err)
				}
				return []*certificates.VerifiableCertificate{
					{
						Certificate: certificates.Certificate{
							Type:         wallet.Base64String("wrong-type"),
							SerialNumber: wallet.Base64String("12345"),
							Subject:      *clientIdentityKey.PublicKey,
							Certifier:    *certifierKey,
							Fields: map[wallet.CertificateFieldNameUnder50Bytes]wallet.Base64String{
								"age":     wallet.Base64String("21"),
								"country": wallet.Base64String("Switzerland"),
							},
							Signature: []byte("mocksignature"),
						},
						Keyring: map[wallet.CertificateFieldNameUnder50Bytes]wallet.Base64String{},
					},
				}
			}(),
			expectedStatus: http.StatusForbidden,
		},
		{
			name: "missing age field",
			certificates: func() []*certificates.VerifiableCertificate {
				certifierKey, err := ec.PublicKeyFromString(trustedCertifier)
				if err != nil {
					t.Fatalf("failed to create certifier key: %v", err)
				}
				return []*certificates.VerifiableCertificate{
					{
						Certificate: certificates.Certificate{
							Type:         wallet.Base64String("age-verification"),
							SerialNumber: wallet.Base64String("12345"),
							Subject:      *clientIdentityKey.PublicKey,
							Certifier:    *certifierKey,
							Fields: map[wallet.CertificateFieldNameUnder50Bytes]wallet.Base64String{
								"country": wallet.Base64String("Switzerland"),
								// Age field missing
							},
							Signature: []byte("mocksignature"),
						},
						Keyring: map[wallet.CertificateFieldNameUnder50Bytes]wallet.Base64String{},
					},
				}
			}(),
			expectedStatus: http.StatusForbidden,
		},
		{
			name: "underage certificate",
			certificates: func() []*certificates.VerifiableCertificate {
				certifierKey, err := ec.PublicKeyFromString(trustedCertifier)
				if err != nil {
					t.Fatalf("failed to create certifier key: %v", err)
				}
				return []*certificates.VerifiableCertificate{
					{
						Certificate: certificates.Certificate{
							Type:         wallet.Base64String("age-verification"),
							SerialNumber: wallet.Base64String("12345"),
							Subject:      *clientIdentityKey.PublicKey,
							Certifier:    *certifierKey,
							Fields: map[wallet.CertificateFieldNameUnder50Bytes]wallet.Base64String{
								"age":     wallet.Base64String("17"), // Underage
								"country": wallet.Base64String("Switzerland"),
							},
							Signature: []byte("mocksignature"),
						},
						Keyring: map[wallet.CertificateFieldNameUnder50Bytes]wallet.Base64String{},
					},
				}
			}(),
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "empty certificates",
			certificates:   []*certificates.VerifiableCertificate{},
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			certResponse, err := server.SendCertificateResponse(t, clientWallet, tc.certificates)
			require.NoError(t, err)

			require.Equal(t, tc.expectedStatus, certResponse.StatusCode,
				"Expected HTTP status %d but got %d for certificate case: %s",
				tc.expectedStatus, certResponse.StatusCode, tc.name)

			request, err := http.NewRequest(http.MethodGet, server.URL()+"/ping", nil)
			require.NoError(t, err)
			response, err := server.SendGeneralRequest(t, request)
			require.NoError(t, err)
			assert.NotAuthorized(t, response)
		})
	}
}
