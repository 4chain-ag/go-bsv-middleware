package main

import (
	"context"
	"encoding/json"
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
	fmt.Println("BSV Auth middleware - Demo")
	logHandler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := slog.New(logHandler)

	sPrivKey, err := ec.PrivateKeyFromHex(serverPrivateKeyHex)
	if err != nil {
		panic(err)
	}

	serverWallet, err := exampleWallet.NewExampleWallet(exampleWallet.ExampleWalletArgs{
		Type:       exampleWallet.ExampleWalletArgsTypePrivateKey,
		PrivateKey: sPrivKey,
	})
	if err != nil {
		panic(err)
	}
	fmt.Println("✓ Server mockWallet created")

	certificateToRequest := &sdkUtils.RequestedCertificateSet{
		Certifiers: []string{trustedCertifier},
		CertificateTypes: map[string][]string{
			"age-verification": {"age"},
		},
	}

	opts := middleware.Config{
		AllowUnauthenticated:   false,
		Logger:                 logger,
		Wallet:                 serverWallet,
		OnCertificatesReceived: onCertificatesReceived,
		CertificatesToRequest:  certificateToRequest,
	}
	middleware, err := middleware.New(opts)
	if err != nil {
		panic(err)
	}

	fmt.Println("✓ Auth middleware created")

	mux := http.NewServeMux()
	mux.Handle("/", middleware.Handler(http.HandlerFunc(pingHandler)))
	mux.Handle("/ping", middleware.Handler(http.HandlerFunc(pingHandler)))

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

	fmt.Println("✓ HTTP Server started")

	cPrivKey, err := ec.PrivateKeyFromHex(clientPrivateKeyHex)
	if err != nil {
		panic(err)
	}
	clientWallet, err := exampleWallet.NewExampleWallet(exampleWallet.ExampleWalletArgs{
		Type:       exampleWallet.ExampleWalletArgsTypePrivateKey,
		PrivateKey: cPrivKey,
	})
	if err != nil {
		panic(err)
	}
	fmt.Println("✓ Client mockWallet created")

	fmt.Println("\n📡 STEP 1: Sending non general request to /.well-known/auth endpoint")
	responseData := callInitialRequest(clientWallet)
	fmt.Println("✓ Auth completed")

	fmt.Println("\n📡 STEP 2: Sending general request to test authorization")
	callPingEndpoint(clientWallet, responseData)
	fmt.Println("✓ General request completed")

	// fmt.Println("\n📡 STEP 3: Sending certificates")
	// sendCertificate2(context.Background(), clientWallet, responseData)
	// fmt.Println("✓ General request completed")

	// fmt.Println("\n📡 STEP 4: Sending general request to test authorization")
	// callPingEndpoint(clientWallet, responseData)
	// fmt.Println("✓ General request completed")
}

func pingHandler(w http.ResponseWriter, r *http.Request) {
	_, err := w.Write([]byte("Pong!"))
	if err != nil {
		log.Printf("Error writing ping response: %v", err)
	}
}

// Makes the initial authentication request
func callInitialRequest(clientWallet wallet.Interface) *auth.AuthMessage {
	initialRequest := utils.PrepareInitialRequestBody(context.Background(), clientWallet)
	url := "http://localhost" + serverPort + "/.well-known/auth"

	client := resty.New()
	var result auth.AuthMessage
	var errMsg any

	resp, err := client.R().
		SetHeader("Content-Type", "application/json").
		SetBody(initialRequest).
		SetResult(&result).
		SetError(&errMsg).
		Post(url)

	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}

	if resp.IsError() {
		log.Fatalf("Request failed: Status %d, Body: %s", resp.StatusCode(), resp.String())
	}

	fmt.Println("Response from server: ", resp.String())

	fmt.Println("🔑 Response Headers:")
	for key, value := range resp.Header() {
		lowerKey := strings.ToLower(key)
		if strings.Contains(lowerKey, "x-bsv-auth") {
			fmt.Println(lowerKey, strings.Join(value, ", "))
		}
	}

	return &result
}

// Makes an authenticated request to the ping endpoint
func callPingEndpoint(clientWallet wallet.Interface, response *auth.AuthMessage) {
	url := "http://localhost" + serverPort + "/ping"

	modifiedResponse := *response
	modifiedResponse.InitialNonce = response.Nonce

	requestData := utils.RequestData{
		Method: http.MethodGet,
		URL:    url,
	}

	headers, err := utils.PrepareGeneralRequestHeaders(context.Background(), clientWallet, &modifiedResponse, requestData)
	if err != nil {
		log.Fatalf("Failed to prepare general request headers: %v", err)
	}

	fmt.Println("🔑 Request headers")
	for key, value := range headers {
		fmt.Println(key, value)
	}

	client := resty.New()
	resp, err := client.R().
		SetHeaders(headers).
		Get(url)

	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}

	log.Printf("Response from server: %s", resp.String())

	fmt.Println("🔑 Response Headers:")
	for key, value := range resp.Header() {
		lowerKey := strings.ToLower(key)
		if strings.Contains(lowerKey, "x-bsv-auth") {
			fmt.Println(lowerKey, strings.Join(value, ", "))
		}
	}

	if resp.IsError() {
		log.Printf("Warning: Received non-success status from /ping: %d", resp.StatusCode())
	}
}

// func sendCertificate(mockedWallet wallet.WalletInterface, response *auth.AuthMessage) *resty.Response {
// 	url := "http://localhost:8080/.well-known/auth"

// 	identityPubKey, err := mockedWallet.GetPublicKey(&wallet.GetPublicKeyArgs{IdentityKey: true}, "")
// 	if err != nil {
// 		log.Fatalf("Failed to get identity key: %v", err)
// 	}
// 	identityKey := identityPubKey.PublicKey.ToDERHex()

// 	certificates := []wallet.VerifiableCertificate{
// 		{
// 			Certificate: wallet.Certificate{
// 				Type:         "age-verification",
// 				SerialNumber: "12345",
// 				Subject:      identityKey,
// 				Certifier:    trustedCertifier,
// 				Fields: map[string]any{
// 					"age": "21",
// 				},
// 				Signature: "mocksignature",
// 			},
// 			Keyring: map[string]string{"age": "symmetricKeyToField"},
// 		},
// 	}

// 	newNonce, err := mockedWallet.CreateNonce(context.Background())
// 	if err != nil {
// 		log.Fatalf("Failed to create nonce: %v", err)
// 	}

// 	requestID := make([]byte, 32)
// 	_, err = rand.Read(requestID)
// 	if err != nil {
// 		log.Fatalf("Failed to generate random request ID: %v", err)
// 	}
// 	encodedRequestID := base64.StdEncoding.EncodeToString(requestID)

// 	var signatureData bytes.Buffer

// 	signatureData.Write(requestID)

// 	certBytes, err := json.Marshal(certificates)
// 	if err != nil {
// 		log.Fatalf("Failed to marshal certificates: %v", err)
// 	}
// 	signatureData.Write(certBytes)

// 	req, err := http.NewRequest(http.MethodPost, url, nil)
// 	if err != nil {
// 		log.Fatalf("Failed to create request: %v", err)
// 	}
// 	err = utils.WriteRequestData(req, &signatureData)
// 	if err != nil {
// 		log.Fatalf("Failed to write request data: %v", err)
// 	}

// 	serverKey, err := ec.PublicKeyFromString(response.IdentityKey)
// 	if err != nil {
// 		log.Fatalf("Failed to parse server identity key: %v", err)
// 	}

// 	baseArgs := wallet.EncryptionArgs{
// 		ProtocolID: wallet.DefaultAuthProtocol,
// 		Counterparty: wallet.Counterparty{
// 			Type:         wallet.CounterpartyTypeOther,
// 			Counterparty: serverKey,
// 		},
// 		KeyID: fmt.Sprintf("%s %s", newNonce, response.InitialNonce),
// 	}

// 	createSignatureArgs := &wallet.CreateSignatureArgs{
// 		EncryptionArgs: baseArgs,
// 		Data:           signatureData.Bytes(),
// 	}

// 	signatureResult, err := mockedWallet.CreateSignature(createSignatureArgs, "")
// 	if err != nil {
// 		log.Fatalf("Failed to create signature: %v", err)
// 	}
// 	signatureBytes := signatureResult.Signature.Serialize()
// 	signatureHex := hex.EncodeToString(signatureBytes)

// 	certificateResponseMsg := auth.AuthMessage{
// 		Version:      "0.1",
// 		MessageType:  "certificateResponse",
// 		IdentityKey:  identityKey,
// 		Nonce:        &newNonce,
// 		YourNonce:    response.InitialNonce,
// 		Certificates: certificates,
// 		Signature:    &signatureBytes,
// 	}

// 	headers := map[string]string{
// 		"x-bsv-auth-version":      "0.1",
// 		"x-bsv-auth-identity-key": identityKey,
// 		"x-bsv-auth-nonce":        newNonce,
// 		"x-bsv-auth-your-nonce":   response.InitialNonce,
// 		"x-bsv-auth-signature":    signatureHex,
// 		"x-bsv-auth-request-id":   encodedRequestID,
// 		"x-bsv-auth-message-type": "certificateResponse",
// 	}

// 	fmt.Println("🔑 Request headers")
// 	for key, value := range headers {
// 		fmt.Println(key, value)
// 	}

// 	client := resty.New()
// 	var result auth.AuthMessage
// 	var errMsg any

// 	resp, err := client.R().
// 		SetHeaders(headers).
// 		SetHeader("Content-Type", "application/json").
// 		SetBody(certificateResponseMsg).
// 		SetResult(&result).
// 		SetError(&errMsg).
// 		Post(url)

// 		// 	if err != nil {
// 		// 		log.Fatalf("Request failed: %v", err)
// 		// 	}

// 		// 	if resp.IsError() {
// 		// 		log.Fatalf("Request failed: Status %d, Body: %s", resp.StatusCode(), resp.String())
// 		// 	}

// 	log.Printf("Response from server: %s", resp.String())

// 	fmt.Println("🔑 Response Headers:")
// 	for key, value := range resp.Header() {
// 		lowerKey := strings.ToLower(key)
// 		if strings.Contains(lowerKey, "x-bsv-auth") {
// 			fmt.Println(lowerKey, strings.Join(value, ", "))
// 		}
// 	}

//		return resp
//	}
func onCertificatesReceived(
	senderPublicKey string,
	certs []*certificates.VerifiableCertificate,
	req *http.Request,
	res http.ResponseWriter,
	next func()) {

	if certs == nil || len(certs) == 0 {
		slog.Error("No certificates provided")
		res.WriteHeader(http.StatusForbidden)
		res.Write([]byte("No age verification certificate provided"))
		return
	}

	validAge := false

	for i, cert := range certs {
		slog.Info("Certificate received", slog.Int("index", i), slog.Any("certificate", cert))

		subject, err := ec.PrivateKeyFromHex(clientPrivateKeyHex)

		if cert.Certificate.Subject != *subject.PubKey() {
			slog.Error("Certificate subject mismatch",
				slog.String("subject", cert.Certificate.Subject.ToDERHex()),
				slog.String("senderPublicKey", senderPublicKey))
			continue
		}
		certifier, err := ec.PrivateKeyFromHex(serverPrivateKeyHex)

		if cert.Certificate.Certifier != *certifier.PubKey() {
			slog.Error("Certificate not from trusted certifier")
			continue
		}

		if cert.Certificate.Type != "age-verification" {
			slog.Error("Unexpected certificate type")
			continue
		}

		ageVal, ok := cert.Certificate.Fields["age"]
		if !ok {
			slog.Error("No age field found")
			continue
		}

		age, err := strconv.Atoi(fmt.Sprintf("%v", ageVal))
		if err != nil {
			slog.Error("Invalid age format", slog.Any("ageField", ageVal))
			continue
		}

		if age < 18 {
			slog.Error("Age below 18", slog.Int("age", age))
			continue
		}

		slog.Info("Age verified", slog.Int("age", age))
		validAge = true
		break
	}

	if !validAge {
		slog.Error("Age verification failed")
		res.WriteHeader(http.StatusForbidden)
		res.Write([]byte("Age verification failed. Must be 18 or older."))
		return
	}

	slog.Info("Age verification successful")
	if next != nil {
		next()
	}
}

// Makes an authenticated request to the ping endpoint
func sendCertificate2(ctx context.Context, clientWallet wallet.Interface, response *auth.AuthMessage) {
	url := "http://localhost:8080/.well-known/auth"

	modifiedResponse := *response
	modifiedResponse.InitialNonce = response.Nonce

	identityPubKey, err := clientWallet.GetPublicKey(ctx, wallet.GetPublicKeyArgs{IdentityKey: true}, "")
	if err != nil {
		log.Fatalf("Failed to get identity key: %v", err)
	}
	identityKey := identityPubKey.PublicKey
	certifier, err := ec.PrivateKeyFromHex(serverPrivateKeyHex)

	certificates := []certificates.VerifiableCertificate{
		{
			Certificate: certificates.Certificate{
				Type:         "age-verification",
				SerialNumber: "12345",
				Subject:      *identityKey,
				Certifier:    *certifier.PubKey(),
				Fields: map[wallet.CertificateFieldNameUnder50Bytes]wallet.Base64String{
					"age": "21",
				},
				Signature: []byte("mocksignature"),
			},
			Keyring: map[wallet.CertificateFieldNameUnder50Bytes]wallet.Base64String{"age": "symmetricKeyToField"},
		},
	}

	certBytes, err := json.Marshal(certificates)
	if err != nil {
		log.Fatalf("Failed to marshal certificates: %v", err)
	}

	requestData := utils.RequestData{
		Method: http.MethodPost,
		URL:    url,
		Body:   certBytes,
	}

	headers, err := utils.PrepareCertificateResponseHeaders(context.Background(), clientWallet, &modifiedResponse, requestData)
	if err != nil {
		log.Fatalf("Failed to prepare general request headers: %v", err)
	}

	fmt.Println("🔑 Request headers")
	for key, value := range headers {
		fmt.Println(key, value)
	}

	client := resty.New()
	resp, err := client.R().
		SetHeaders(headers).
		Get(url)

	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}

	log.Printf("Response from server: %s", resp.String())

	fmt.Println("🔑 Response Headers:")
	for key, value := range resp.Header() {
		lowerKey := strings.ToLower(key)
		if strings.Contains(lowerKey, "x-bsv-auth") {
			fmt.Println(lowerKey, strings.Join(value, ", "))
		}
	}

	if resp.IsError() {
		log.Printf("Warning: Received non-success status from /ping: %d", resp.StatusCode())
	}
}
