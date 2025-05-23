package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	exampleWallet "github.com/bsv-blockchain/go-bsv-middleware-examples/example-wallet"
	middleware "github.com/bsv-blockchain/go-bsv-middleware/pkg/middleware/auth"

	"github.com/bsv-blockchain/go-sdk/auth/certificates"
	sdkUtils "github.com/bsv-blockchain/go-sdk/auth/utils"
	"github.com/bsv-blockchain/go-sdk/wallet"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/utils"
	"github.com/bsv-blockchain/go-sdk/auth"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"

	"github.com/go-resty/resty/v2"
)

const (
	serverPrivateKeyHex = "5a4d867377bd44eba1cecd0806c16f24e293f7e218c162b1177571edaeeaecef"
	clientPrivateKeyHex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	serverPort          = ":8080"
	trustedCertifier    = "02certifieridentitykey00000000000000000000000000000000000000000000000"
)

func main() {
	log.Println("BSV Auth middleware - Demo")
	logHandler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := slog.New(logHandler)

	sPrivKey, err := ec.PrivateKeyFromHex(serverPrivateKeyHex)
	if err != nil {
		log.Fatalf("Failed to parse server private key: %v", err)
	}

	serverWallet, err := exampleWallet.NewExtendedProtoWallet(sPrivKey)
	if err != nil {
		log.Fatalf("Failed to create server wallet: %v", err)
	}
	log.Println("✓ Server wallet created")

	certificateToRequest := &sdkUtils.RequestedCertificateSet{
		Certifiers: []string{trustedCertifier},
		CertificateTypes: map[string][]string{
			"age-verification": {"age"},
		},
	}

	var onCertificatesReceived auth.OnCertificateReceivedCallback = onCertificatesReceivedFunc

	opts := middleware.Config{
		AllowUnauthenticated:   false,
		Logger:                 logger,
		Wallet:                 serverWallet,
		OnCertificatesReceived: onCertificatesReceived,
		CertificatesToRequest:  certificateToRequest,
	}
	authMiddleware, err := middleware.New(opts)
	if err != nil {
		log.Fatalf("Failed to create auth middleware: %v", err)
	}

	log.Println("✓ Auth middleware created")

	mux := http.NewServeMux()
	mux.Handle("/", authMiddleware.Handler(http.HandlerFunc(pingHandler)))
	mux.Handle("/ping", authMiddleware.Handler(http.HandlerFunc(pingHandler)))

	srv := &http.Server{
		Addr:    serverPort,
		Handler: mux,
	}

	go func() {
		logger.Info("Server started", slog.String("addr", srv.Addr))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("Server failed", slog.Any("error", err))
		}
	}()

	time.Sleep(1 * time.Second)
	log.Println("✓ HTTP Server started")

	cPrivKey, err := ec.PrivateKeyFromHex(clientPrivateKeyHex)
	if err != nil {
		log.Fatalf("Failed to parse client private key: %v", err)
	}

	clientWallet, err := exampleWallet.NewExtendedProtoWallet(cPrivKey)
	if err != nil {
		log.Fatalf("Failed to create client wallet: %v", err)
	}

	log.Println("✓ Client wallet created")

	log.Println("\n📡 STEP 1: Sending non general request to /.well-known/auth endpoint")
	responseData, err := callInitialRequest(clientWallet)
	if err != nil {
		log.Fatalf("Failed to call initial request: %v", err)
	}
	log.Println("✓ Auth completed")

	log.Println("\n📡 STEP 2: Sending general request to test authorization")
	if err := callPingEndpoint(clientWallet, responseData); err != nil {
		log.Fatalf("Failed to call ping endpoint: %v", err)
	}
	log.Println("✓ General request completed")

	log.Println("\n📡 STEP 3: Sending certificates")
	if err := sendCertificate(context.Background(), clientWallet, responseData); err != nil {
		log.Fatalf("Failed to send certificate: %v", err)
	}
	log.Println("✓ Certificate request completed")
}

// pingHandler handles ping requests and returns a simple "Pong!" response
func pingHandler(w http.ResponseWriter, r *http.Request) {
	_, err := w.Write([]byte("Pong!"))
	if err != nil {
		log.Printf("Error writing ping response: %v", err)
	}
}

// callInitialRequest sends the initial authentication request to the /.well-known/auth endpoint
func callInitialRequest(clientWallet wallet.Interface) (*auth.AuthMessage, error) {
	initialRequest := utils.PrepareInitialRequestBody(context.Background(), clientWallet)
	url := "http://localhost" + serverPort + "/.well-known/auth"

	client := resty.New()
	var result auth.AuthMessage

	resp, err := client.R().
		SetHeader("Content-Type", "application/json").
		SetBody(initialRequest).
		SetResult(&result).
		Post(url)

	if err != nil {
		log.Printf("Request failed: %v", err)
		return nil, err
	}

	if resp.IsError() {
		errMsg := resp.String()
		log.Printf("Server returned error (%d): %s", resp.StatusCode(), errMsg)
		return nil, errors.New("server error occurred")
	}

	log.Printf("Response from server: %s", resp.String())

	log.Println("🔑 Response Headers:")
	for key, value := range resp.Header() {
		lowerKey := strings.ToLower(key)
		if strings.Contains(lowerKey, "x-bsv-auth") {
			log.Printf("%s: %s", lowerKey, strings.Join(value, ", "))
		}
	}

	return &result, nil
}

// callPingEndpoint sends a general request to the /ping endpoint to test authorization
func callPingEndpoint(clientWallet wallet.Interface, response *auth.AuthMessage) error {
	url := "http://localhost" + serverPort + "/ping"

	modifiedResponse := *response
	modifiedResponse.InitialNonce = response.Nonce

	requestData := utils.RequestData{
		Method: http.MethodGet,
		URL:    url,
	}

	headers, err := utils.PrepareGeneralRequestHeaders(context.Background(), clientWallet, &modifiedResponse, requestData)
	if err != nil {
		log.Printf("Failed to prepare general request headers: %v", err)
		return err
	}

	log.Println("🔑 Request headers")
	for key, value := range headers {
		log.Printf("%s: %s", key, value)
	}

	client := resty.New()
	resp, err := client.R().
		SetHeaders(headers).
		Get(url)

	if err != nil {
		log.Printf("Request failed: %v", err)
		return err
	}

	log.Printf("Response from server: %s", resp.String())

	log.Println("🔑 Response Headers:")
	for key, value := range resp.Header() {
		lowerKey := strings.ToLower(key)
		if strings.Contains(lowerKey, "x-bsv-auth") {
			log.Printf("%s: %s", lowerKey, strings.Join(value, ", "))
		}
	}

	if resp.IsError() {
		log.Printf("Warning: Received non-success status from /ping: %d", resp.StatusCode())
		return fmt.Errorf("ping endpoint returned status %d", resp.StatusCode())
	}

	return nil
}

// sendCertificate creates and sends a certificate response to the server
func sendCertificate(ctx context.Context, clientWallet wallet.Interface, response *auth.AuthMessage) error {
	certificateResponse, err := createCertificateResponse(ctx, clientWallet, response)
	if err != nil {
		log.Printf("Failed to create certificate response: %v", err)
		return err
	}

	resp, err := sendCertificateRequest(ctx, clientWallet, response, certificateResponse)
	if err != nil {
		log.Printf("Failed to send certificate request: %v", err)
		return err
	}

	log.Printf("Response from server: %s", resp.String())
	return nil
}

// createCertificateResponse creates a certificate response message with verifiable certificates
func createCertificateResponse(ctx context.Context, clientWallet wallet.Interface, authResponse *auth.AuthMessage) (*auth.AuthMessage, error) {
	newNonce, err := generateBase64Nonce(32)
	if err != nil {
		log.Printf("Failed to generate nonce: %v", err)
		return nil, err
	}
	log.Printf("New Nonce (base64): %s", newNonce)

	identityPubKey, err := clientWallet.GetPublicKey(ctx, wallet.GetPublicKeyArgs{IdentityKey: true}, "")
	if err != nil {
		log.Printf("Failed to get identity key: %v", err)
		return nil, err
	}
	identityKey := identityPubKey.PublicKey

	certs, err := createVerifiableCertificates(identityKey)
	if err != nil {
		log.Printf("Failed to create certificates: %v", err)
		return nil, err
	}

	certBytes, err := json.Marshal(certs)
	if err != nil {
		log.Printf("Failed to marshal certificates: %v", err)
		return nil, err
	}

	keyID := fmt.Sprintf("%s %s", newNonce, authResponse.Nonce)
	signature, err := signCertificateResponse(ctx, clientWallet, keyID, authResponse.IdentityKey, certBytes)
	if err != nil {
		log.Printf("Failed to sign certificate response: %v", err)
		return nil, err
	}

	return &auth.AuthMessage{
		Version:      "0.1",
		MessageType:  "certificateResponse",
		IdentityKey:  identityKey,
		Nonce:        newNonce,
		YourNonce:    authResponse.Nonce,
		Certificates: certs,
		Signature:    signature,
	}, nil
}

// generateBase64Nonce generates a random base64-encoded nonce of the specified size
func generateBase64Nonce(size int) (string, error) {
	randomBytes := make([]byte, size)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(randomBytes), nil
}

// createVerifiableCertificates creates test verifiable certificates for age verification
func createVerifiableCertificates(identityKey *ec.PublicKey) ([]*certificates.VerifiableCertificate, error) {
	certifier, err := ec.PrivateKeyFromHex(serverPrivateKeyHex)
	if err != nil {
		log.Printf("Failed to get certifier key: %v", err)
		return nil, err
	}

	serialNumber, err := generateBase64Nonce(16)
	if err != nil {
		log.Printf("Failed to generate serial number: %v", err)
		return nil, err
	}

	certificate := certificates.Certificate{
		Type:         wallet.Base64String(encodeToBase64("age-verification")),
		SerialNumber: wallet.Base64String(serialNumber),
		Subject:      *identityKey,
		Certifier:    *certifier.PubKey(),
		Fields: map[wallet.CertificateFieldNameUnder50Bytes]wallet.Base64String{
			"age": wallet.Base64String(encodeToBase64("21")),
		},
		// For testing purposes, we are not using a real signature
		// We receive warning about the signature being invalid, but we are ignoring it here
		// In a real scenario, this should be a valid signature from the certifier
		Signature: []byte("mocksignature"),
	}

	return []*certificates.VerifiableCertificate{
		{
			Certificate: certificate,
			Keyring: map[wallet.CertificateFieldNameUnder50Bytes]wallet.Base64String{
				"age": wallet.Base64String(encodeToBase64("symmetricKeyToField")),
			},
		},
	}, nil
}

// encodeToBase64 encodes a string to base64
func encodeToBase64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// signCertificateResponse signs the certificate response data with the client wallet
func signCertificateResponse(ctx context.Context, clientWallet wallet.Interface, keyID string, counterpartyKey *ec.PublicKey, data []byte) ([]byte, error) {
	sigResult, err := clientWallet.CreateSignature(ctx, wallet.CreateSignatureArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID: wallet.Protocol{
				SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty,
				Protocol:      auth.AUTH_PROTOCOL_ID,
			},
			KeyID: keyID,
			Counterparty: wallet.Counterparty{
				Type:         wallet.CounterpartyTypeOther,
				Counterparty: counterpartyKey,
			},
		},
		Data: data,
	}, "")

	if err != nil {
		return nil, err
	}

	return sigResult.Signature.Serialize(), nil
}

// sendCertificateRequest sends the certificate response to the server
func sendCertificateRequest(ctx context.Context, clientWallet wallet.Interface, authResponse *auth.AuthMessage, certificateResponse *auth.AuthMessage) (*resty.Response, error) {
	url := "http://localhost" + serverPort + "/.well-known/auth"
	modifiedResponse := *authResponse
	modifiedResponse.InitialNonce = authResponse.Nonce

	jsonBody, err := json.Marshal(certificateResponse)
	if err != nil {
		log.Printf("Failed to marshal certificate response: %v", err)
		return nil, err
	}

	requestData := utils.RequestData{
		Method: http.MethodPost,
		URL:    url,
		Body:   jsonBody,
	}
	headers, err := utils.PrepareCertificateResponseHeaders(ctx, clientWallet, &modifiedResponse, requestData)
	if err != nil {
		log.Printf("Failed to prepare headers: %v", err)
		return nil, err
	}

	client := resty.New()
	resp, err := client.R().
		SetHeaders(headers).
		SetHeader("Content-Type", "application/json").
		SetBody(jsonBody).
		Post(url)
	if err != nil {
		log.Printf("Request failed: %v", err)
		return nil, err
	}

	if resp.IsError() {
		log.Printf("Warning: Received non-success status: %d", resp.StatusCode())
	}

	return resp, nil
}

// onCertificatesReceivedFunc handles received certificates and validates age verification
func onCertificatesReceivedFunc(
	senderPublicKey *ec.PublicKey,
	certs []*certificates.VerifiableCertificate) error {
	if certs == nil || len(certs) == 0 {
		log.Printf("No certificates provided")
		return fmt.Errorf("no age verification certificate provided")
	}

	validAge := false
	for i, cert := range certs {
		log.Printf("Certificate received at index %d", i)

		subject, err := ec.PrivateKeyFromHex(clientPrivateKeyHex)
		if err != nil {
			log.Printf("Failed to parse client private key: %v", err)
			continue
		}

		if cert.Certificate.Subject.ToDERHex() != subject.PubKey().ToDERHex() {
			log.Printf("Certificate subject mismatch: got %s, expected %s",
				cert.Certificate.Subject.ToDERHex(), subject.PubKey().ToDERHex())
			continue
		}

		certifier, err := ec.PrivateKeyFromHex(serverPrivateKeyHex)
		if err != nil {
			log.Printf("Failed to parse server private key: %v", err)
			continue
		}

		if cert.Certificate.Certifier.ToDERHex() != certifier.PubKey().ToDERHex() {
			log.Printf("Certificate not from trusted certifier")
			continue
		}

		// base64 encoded "age-verification"
		if cert.Certificate.Type != "YWdlLXZlcmlmaWNhdGlvbg==" {
			log.Printf("Unexpected certificate type: %s", cert.Certificate.Type)
			continue
		}

		ageVal, ok := cert.Certificate.Fields["age"]
		if !ok {
			log.Printf("No age field found")
			continue
		}

		ageArrByte, err := base64.StdEncoding.DecodeString(fmt.Sprintf("%v", ageVal))
		if err != nil {
			log.Printf("Failed to decode age field: %v", err)
			continue
		}

		age, err := strconv.Atoi(string(ageArrByte))
		if err != nil {
			log.Printf("Invalid age format: %v", ageVal)
			continue
		}

		if age < 18 {
			log.Printf("Age below 18: %d", age)
			continue
		}

		log.Printf("Age verified: %d", age)
		validAge = true
		break
	}

	if !validAge {
		log.Printf("Age verification failed")
		return fmt.Errorf("age verification failed: must be 18 or older")
	}

	log.Printf("Age verification successful")
	return nil
}
