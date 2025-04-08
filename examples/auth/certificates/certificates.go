package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/4chain-ag/go-bsv-middleware/pkg/middleware/auth"
	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
	walletFixtures "github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet/test"
	"github.com/4chain-ag/go-bsv-middleware/pkg/test/mocks"
	"github.com/4chain-ag/go-bsv-middleware/pkg/transport"
)

const serverAddress = "http://localhost:8080"
const trustedCertifier = "02certifieridentitykey00000000000000000000000000000000000000000000000"

func main() {
	// ========== Server Setup ==========
	fmt.Println("============================================================")
	fmt.Println("🔒 AGE VERIFICATION DEMO - SECURE AUTHENTICATION FLOW")
	fmt.Println("============================================================")

	// Initialize logger
	logHandler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := slog.New(logHandler)

	// Define the certificate types and certifier expected
	certificateToRequest := transport.RequestedCertificateSet{
		Certifiers: []string{trustedCertifier},
		Types: map[string][]string{
			"age-verification": {"age"},
		},
	}

	// Middleware callback for processing received certificates
	onCertificatesReceived := func(
		senderPublicKey string,
		certs *[]wallet.VerifiableCertificate,
		req *http.Request,
		res http.ResponseWriter,
		next func()) {

		// Reject if no certificate was provided
		if certs == nil || len(*certs) == 0 {
			logger.Error("No certificates provided")
			res.WriteHeader(http.StatusForbidden)
			res.Write([]byte("No age verification certificate provided"))
			return
		}

		validAge := false

		// Validate each certificate
		for i, cert := range *certs {
			logger.Info("Certificate received", slog.Int("index", i), slog.Any("certificate", cert))

			// Ensure the certificate subject matches the sender
			if cert.Certificate.Subject != senderPublicKey {
				logger.Error("Certificate subject mismatch",
					slog.String("subject", cert.Certificate.Subject),
					slog.String("senderPublicKey", senderPublicKey))
				continue
			}

			// Check certifier
			if cert.Certificate.Certifier != trustedCertifier {
				logger.Error("Certificate not from trusted certifier")
				continue
			}

			// Check type
			if cert.Certificate.Type != "age-verification" {
				logger.Error("Unexpected certificate type")
				continue
			}

			// Extract and parse age
			ageVal, ok := cert.Certificate.Fields["age"]
			if !ok {
				logger.Error("No age field found")
				continue
			}

			age, err := strconv.Atoi(fmt.Sprintf("%v", ageVal))
			if err != nil {
				logger.Error("Invalid age format", slog.Any("ageField", ageVal))
				continue
			}

			// Validate age
			if age < 18 {
				logger.Error("Age below 18", slog.Int("age", age))
				continue
			}

			logger.Info("Age verified", slog.Int("age", age))
			validAge = true
			break
		}

		// Block request if no valid cert
		if !validAge {
			logger.Error("Age verification failed")
			res.WriteHeader(http.StatusForbidden)
			res.Write([]byte("Age verification failed. Must be 18 or older."))
			return
		}

		// Continue request if age is verified
		logger.Info("Age verification successful")
		if next != nil {
			next()
		}
	}

	// Configure authentication middleware
	opts := auth.Config{
		AllowUnauthenticated:   false,
		Logger:                 logger,
		Wallet:                 wallet.NewMockWallet(true, nil, walletFixtures.DefaultNonces...),
		CertificatesToRequest:  &certificateToRequest,
		OnCertificatesReceived: onCertificatesReceived,
	}
	middleware := auth.New(opts)

	// Setup HTTP routes with middleware
	mux := http.NewServeMux()
	mux.Handle("/", middleware.Handler(http.HandlerFunc(pingHandler)))
	mux.Handle("/ping", middleware.Handler(http.HandlerFunc(pingHandler)))

	// Start HTTP server
	srv := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}
	go func() {
		logger.Info("Server started", slog.String("addr", srv.Addr))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("Server failed", slog.Any("error", err))
		}
	}()

	// Allow server some time to start
	time.Sleep(1 * time.Second)
	fmt.Println("\n✅ Server initialized successfully on http://localhost:8080")
	fmt.Println("   Protected endpoints: / and /ping")
	fmt.Println("   Required: Age verification certificate (18+)")

	// ========== Client Simulation ==========
	fmt.Println("\n============================================================")
	fmt.Println("🧪 SIMULATING CLIENT AUTHENTICATION FLOW")
	fmt.Println("============================================================")

	// Create mocked client wallet
	mockedWallet := wallet.NewMockWallet(true, &walletFixtures.ClientIdentityKey, walletFixtures.ClientNonces...)

	// Step 1: Initial authentication request
	fmt.Println("\n📡 STEP 1: Client initiates authentication handshake")
	responseData := callInitialRequest(mockedWallet)
	fmt.Printf("   ↪ Server responded with identity key: %s...\n", responseData.IdentityKey[:16])

	// Step 2: Try to access protected resource without certificate
	fmt.Println("\n📡 STEP 2: Testing access to protected resource WITHOUT certificate")
	resp := callPingEndpoint(mockedWallet, responseData)
	expectedErrorCode := http.StatusUnauthorized
	if resp.StatusCode != expectedErrorCode {
		fmt.Printf("   ❌ ERROR: Expected status %d, but received: %d\n", expectedErrorCode, resp.StatusCode)
	} else {
		fmt.Printf("   ✅ SUCCESS: Server correctly denied access with status %d (Unauthorized)\n", expectedErrorCode)
	}

	// Step 3: Send valid certificate
	fmt.Println("\n📡 STEP 3: Sending valid age verification certificate")
	response2 := sendCertificate(mockedWallet, responseData.IdentityKey, responseData.InitialNonce)
	if response2.StatusCode != http.StatusOK {
		fmt.Printf("   ❌ ERROR: Certificate submission failed with status: %d\n", response2.StatusCode)
	} else {
		fmt.Println("   ✅ SUCCESS: Server accepted the age verification certificate")
	}

	// Step 4: Try accessing protected resource again (should be allowed now)
	fmt.Println("\n📡 STEP 4: Testing access to protected resource WITH valid certificate")
	resp = callPingEndpoint(mockedWallet, responseData)
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("   ❌ ERROR: Access denied with status: %d\n", resp.StatusCode)
	} else {
		fmt.Println("   ✅ SUCCESS: Server granted access to protected resource")
		fmt.Println("   ↪ Received response: \"Pong!\"")
	}

	fmt.Println("\n============================================================")
	fmt.Println("🎉 DEMO COMPLETED SUCCESSFULLY")
	fmt.Println("============================================================")
}

// ========== Handlers ==========

// Simple test handler to validate access
func pingHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Pong!"))
}

// ========== Client Request Helpers ==========

// Sends the initial authentication request
func callInitialRequest(mockedWallet wallet.WalletInterface) *transport.AuthMessage {
	requestData := mocks.PrepareInitialRequestBody(mockedWallet)
	jsonData, err := json.Marshal(requestData)
	if err != nil {
		log.Fatalf("Failed to marshal request: %v", err)
	}

	url := "http://localhost:8080/.well-known/auth"
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read response: %v", err)
	}
	log.Printf("Initial response: %s", string(body))

	var responseData *transport.AuthMessage
	if err = json.Unmarshal(body, &responseData); err != nil {
		log.Fatalf("Failed to unmarshal response: %v", err)
	}

	return responseData
}

// Sends GET /ping with appropriate authentication headers
func callPingEndpoint(mockedWallet wallet.WalletInterface, response *transport.AuthMessage) *http.Response {
	url := "http://localhost:8080/ping"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatalf("Failed to create request: %v", err)
	}

	// Ensure nonces are set
	if response.InitialNonce == "" {
		response.InitialNonce = *response.Nonce
	}
	if response.Nonce == nil {
		response.Nonce = &response.InitialNonce
	}

	headers, err := mocks.PrepareGeneralRequestHeaders(mockedWallet, response, "/ping", "GET")
	if err != nil {
		panic(err)
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read response: %v", err)
	}
	log.Printf("Ping response: %s", string(body))

	return resp
}

// Sends a valid age-verification certificate to the server
func sendCertificate(clientWallet wallet.WalletInterface, serverIdentityKey, previousNonce string) *http.Response {
	identityKey, err := clientWallet.GetPublicKey(context.Background(), wallet.GetPublicKeyOptions{IdentityKey: true})
	if err != nil {
		log.Fatalf("Failed to get identity key: %v", err)
	}

	nonce, err := clientWallet.CreateNonce(context.Background())
	if err != nil {
		log.Fatalf("Failed to create nonce: %v", err)
	}

	certificates := &[]wallet.VerifiableCertificate{
		{
			Certificate: wallet.Certificate{
				Type:         "age-verification",
				SerialNumber: "12345",
				Subject:      identityKey,
				Certifier:    trustedCertifier,
				Fields: map[string]any{
					"age": "18",
				},
				Signature: "mocksignature",
			},
			Keyring: map[string]string{"nameOfField": "symmetricKeyToField"},
		},
	}

	// Create and sign AuthMessage
	certMessage := transport.AuthMessage{
		Version:      "0.1",
		MessageType:  "certificateResponse",
		IdentityKey:  identityKey,
		Nonce:        &nonce,
		YourNonce:    &previousNonce,
		Certificates: certificates,
	}
	requestBody, _ := json.Marshal(certMessage)
	signature, _ := clientWallet.CreateSignature(context.Background(), requestBody, "auth message signature", "initialNonce sessionNonce", identityKey)
	certMessage.Signature = &signature
	requestBody, _ = json.Marshal(certMessage)

	// Create request with headers
	headers, _ := mocks.PrepareGeneralRequestHeaders(clientWallet, &certMessage, "/.well-known/auth", "POST")
	req, _ := http.NewRequest("POST", "http://localhost:8080/.well-known/auth", bytes.NewReader(requestBody))
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	log.Printf("Certificate response: %s", string(body))

	return resp
}
