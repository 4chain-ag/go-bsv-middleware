package integrationtests

import (
	"errors"
	"net/http"
	"strconv"
	"testing"

	"github.com/bsv-blockchain/go-bsv-middleware/test/assert"
	"github.com/bsv-blockchain/go-bsv-middleware/test/mocks"
	"github.com/bsv-blockchain/go-sdk/auth"
	"github.com/bsv-blockchain/go-sdk/auth/certificates"
	sdkUtils "github.com/bsv-blockchain/go-sdk/auth/utils"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	primitives "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
)

const (
	serverPrivateKeyHex = "5a4d867377bd44eba1cecd0806c16f24e293f7e218c162b1177571edaeeaecef"
	clientPrivateKeyHex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	serverPort          = ":8080"
)

var (
	trustedCertifier, _ = primitives.PublicKeyFromString(mocks.ServerIdentityKey)
	clientPrivateKey, _ = primitives.PrivateKeyFromHex(mocks.ClientPrivateKeyHex)
	clientIdentityKey   = clientPrivateKey.PubKey()
)

func TestAuthMiddleware_InvalidCertificateHandling(t *testing.T) {
	// given
	certificateRequirements := &sdkUtils.RequestedCertificateSet{
		Certifiers: []string{trustedCertifier.ToDERHex()},
		CertificateTypes: sdkUtils.RequestedCertificateTypeIDAndFieldList{
			"age-verification": []string{"age", "country"},
		},
	}

	onCertificatesReceived := func(senderPublicKey *ec.PublicKey, certs []*certificates.VerifiableCertificate) error {
		if len(certs) == 0 {
			return errors.New("no certificates received")
		}

		cert := (certs)[0]

		if cert.Certificate.Certifier.ToDERHex() != trustedCertifier.ToDERHex() {
			return errors.New("invalid certifier")
		}

		if string(cert.Certificate.Type) != "age-verification" {
			return errors.New("invalid certificate type")
		}

		ageValue, ok := cert.Certificate.Fields["age"]
		if !ok {
			return errors.New("missing age field")
		}

		age, err := strconv.Atoi(string(ageValue))
		if err != nil || age < 18 {
			return errors.New("underage certificate")
		}
		return nil
	}

	sessionManager := mocks.NewMockableSessionManager()
	serverWallet := mocks.NewMockableWallet()

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
				certifierKey, err := ec.PublicKeyFromString(trustedCertifier.ToDERHex())
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
				certifierKey, err := ec.PublicKeyFromString(trustedCertifier.ToDERHex())
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
				certifierKey, err := ec.PublicKeyFromString(trustedCertifier.ToDERHex())
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
			serverWallet.OnCreateNonceOnce(mocks.DefaultNonces[0], nil)
			serverWallet.OnCreateSignatureOnce(prepareExampleSignature(t), nil)
			serverWallet.OnGetPublicKeyOnce(prepareExampleIdentityKey(t), nil)
			serverWallet.OnCreateHmacOnce(&wallet.CreateHmacResult{
				Hmac: []byte("mockhmacsignature"),
			}, nil)
			serverWallet.OnVerifySignatureOnce(&wallet.VerifySignatureResult{
				Valid: true,
			}, nil)

			sessionManager.OnGetSessionOnce("02ba6965682077505d33a05e2206007e4795c045faa439fc3629d05dfb50c0bcb1", &auth.PeerSession{
				IsAuthenticated: true,
				SessionNonce:    mocks.DefaultNonces[0],
				PeerNonce:       mocks.DefaultNonces[0],
				PeerIdentityKey: clientIdentityKey.PublicKey,
				LastUpdate:      1747241090788,
			})
			certResponse, err := server.SendCertificateResponseWithSetNonces(t, clientWallet, tc.certificates, mocks.DefaultNonces[0], mocks.DefaultNonces[0])
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

func TestAuthMiddleware_CertificateHandling(t *testing.T) {
	sessionManager := mocks.NewMockableSessionManager()
	serverWallet := mocks.NewMockableWallet()

	// TODO: Uncomment this when the go-sdk will support sending requested certificates
	// t.Run("initial request with certificate requirements", func(t *testing.T) {
	// 	certificateRequirements := &sdkUtils.RequestedCertificateSet{
	// 		Certifiers: []string{trustedCertifier.ToDERHex()},
	// 		CertificateTypes: sdkUtils.RequestedCertificateTypeIDAndFieldList{
	// 			"age-verification": []string{"age", "country"},
	// 		},
	// 	}

	// 	var onCertificatesReceived auth.OnCertificateReceivedCallback = func(senderPublicKey *ec.PublicKey, certs []*certificates.VerifiableCertificate) error {
	// 		if len(certs) <= 0 {
	// 			return errors.New("no valid certificates")
	// 		}

	// 		return nil
	// 	}

	// 	server := mocks.CreateMockHTTPServer(serverWallet, sessionManager, mocks.WithLogger, mocks.WithCertificateRequirements(certificateRequirements, onCertificatesReceived)).
	// 		WithHandler("/", mocks.IndexHandler().WithAuthMiddleware()).
	// 		WithHandler("/ping", mocks.PingHandler().WithAuthMiddleware())
	// 	defer server.Close()

	// 	clientWallet := mocks.CreateClientMockWallet()

	// 	initialRequest := mocks.PrepareInitialRequestBody(t.Context(), clientWallet)
	// 	response, err := server.SendNonGeneralRequest(t, initialRequest.AuthMessage())
	// 	require.NoError(t, err)
	// 	assert.ResponseOK(t, response)
	// 	assert.InitialResponseHeaders(t, response)

	// 	authMessage, err := mocks.MapBodyToAuthMessage(t, response)
	// 	require.NoError(t, err)
	// 	require.NotNil(t, authMessage)

	// 	require.NotNil(t, authMessage.RequestedCertificates, "RequestedCertificates should not be nil")
	// 	require.NotEmpty(t, authMessage.RequestedCertificates.CertificateTypes, "Certificate types should not be empty")
	// 	require.Contains(t, authMessage.RequestedCertificates.CertificateTypes, "age-verification",
	// 		"Certificate types should contain age-verification")
	// 	require.Contains(t, authMessage.RequestedCertificates.Certifiers, trustedCertifier,
	// 		"Certifiers should contain the trusted certifier")
	// })

	t.Run("attempt access without certificate", func(t *testing.T) {
		serverWallet.OnCreateNonceOnce(mocks.DefaultNonces[0], nil)
		serverWallet.OnCreateSignatureOnce(prepareExampleSignature(t), nil)
		serverWallet.OnGetPublicKeyOnce(prepareExampleIdentityKey(t), nil)
		serverWallet.OnCreateHmacOnce(&wallet.CreateHmacResult{
			Hmac: []byte("mockhmacsignature"),
		}, nil)
		serverWallet.OnVerifySignatureOnce(&wallet.VerifySignatureResult{
			Valid: true,
		}, nil)

		sessionManager.OnGetSessionOnce("02ba6965682077505d33a05e2206007e4795c045faa439fc3629d05dfb50c0bcb1", &auth.PeerSession{
			IsAuthenticated: false,
			SessionNonce:    mocks.DefaultNonces[0],
			PeerNonce:       mocks.DefaultNonces[0],
			PeerIdentityKey: clientIdentityKey,
			LastUpdate:      1747241090788,
		})

		certificateRequirements := &sdkUtils.RequestedCertificateSet{
			Certifiers: []string{trustedCertifier.ToDERHex()},
			CertificateTypes: sdkUtils.RequestedCertificateTypeIDAndFieldList{
				"age-verification": []string{"age", "country"},
			},
		}

		var onCertificatesReceived auth.OnCertificateReceivedCallback = func(senderPublicKey *ec.PublicKey, certs []*certificates.VerifiableCertificate) error {
			if len(certs) <= 0 {
				return errors.New("no valid certificates")
			}

			return nil
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
		err = mocks.PrepareGeneralRequestHeadersWithSetNonces(t.Context(), clientWallet, authMessage, request, mocks.DefaultNonces[0], mocks.DefaultNonces[0])
		require.NoError(t, err)

		response, err = server.SendGeneralRequest(t, request)
		require.NoError(t, err)
		assert.BadRequest(t, response)
	})

	t.Run("send certificate and gain access", func(t *testing.T) {
		serverWallet.OnCreateNonceOnce(mocks.DefaultNonces[0], nil)
		serverWallet.OnCreateSignatureOnce(prepareExampleSignature(t), nil)
		serverWallet.OnGetPublicKeyOnce(prepareExampleIdentityKey(t), nil)
		serverWallet.OnCreateHmacOnce(&wallet.CreateHmacResult{
			Hmac: []byte("mockhmacsignature"),
		}, nil)
		serverWallet.OnVerifySignatureOnce(&wallet.VerifySignatureResult{
			Valid: true,
		}, nil)

		sessionManager.OnGetSessionOnce("02ba6965682077505d33a05e2206007e4795c045faa439fc3629d05dfb50c0bcb1", &auth.PeerSession{
			IsAuthenticated: false,
			SessionNonce:    mocks.DefaultNonces[0],
			PeerNonce:       mocks.DefaultNonces[0],
			PeerIdentityKey: clientIdentityKey,
			LastUpdate:      1747241090788,
		})
		certificateRequirements := &sdkUtils.RequestedCertificateSet{
			Certifiers: []string{trustedCertifier.ToDERHex()},
			CertificateTypes: sdkUtils.RequestedCertificateTypeIDAndFieldList{
				"age-verification": []string{"age", "country"},
			},
		}

		var receivedCertificateFlag bool
		var onCertificatesReceived auth.OnCertificateReceivedCallback = func(senderPublicKey *ec.PublicKey, certs []*certificates.VerifiableCertificate) error {
			receivedCertificateFlag = true

			if len(certs) <= 0 {
				return errors.New("no valid certificates")
			}

			return nil
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

		certifierPubKey, err := ec.PublicKeyFromString(trustedCertifier.ToDERHex())
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

		certResponse, err := server.SendCertificateResponseWithSetNonces(t, clientWallet, certificates, mocks.DefaultNonces[0], mocks.DefaultNonces[0])
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, certResponse.StatusCode, "Certificate submission should return 200 OK")
		require.True(t, receivedCertificateFlag, "Certificate received callback should be called")

		request, err := http.NewRequest(http.MethodGet, server.URL()+"/ping", nil)
		require.NoError(t, err)
		err = mocks.PrepareGeneralRequestHeaders(t.Context(), clientWallet, authMessage, request)
		require.NoError(t, err)

		response, err = server.SendGeneralRequest(t, request)
		require.NoError(t, err)
		assert.ResponseOK(t, response)
	})
}
