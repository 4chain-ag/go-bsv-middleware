package main

import (
	"context"
	"errors"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	exampleWallet "github.com/bsv-blockchain/go-bsv-middleware-examples/example-wallet"
	middleware "github.com/bsv-blockchain/go-bsv-middleware/pkg/middleware/auth"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/utils"
	"github.com/bsv-blockchain/go-sdk/auth"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/go-resty/resty/v2"
)

const (
	serverPrivateKeyHex = "5a4d867377bd44eba1cecd0806c16f24e293f7e218c162b1177571edaeeaecef"
	clientPrivateKeyHex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	serverPort          = ":8080"
)

func main() {
	log.Println("BSV Auth middleware - Demo")
	logHandler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := slog.New(logHandler)

	sPrivKey, err := ec.PrivateKeyFromHex(serverPrivateKeyHex)
	if err != nil {
		log.Fatalf("Failed to create server private key: %v", err)
	}

	serverWallet, err := exampleWallet.NewExtendedProtoWallet(sPrivKey)
	if err != nil {
		log.Fatalf("Failed to create server wallet: %v", err)
	}

	log.Println("✓ Server wallet created")

	opts := middleware.Config{
		AllowUnauthenticated: false,
		Logger:               logger,
		Wallet:               serverWallet,
	}
	midd, err := middleware.New(opts)
	if err != nil {
		log.Fatalf("Failed to create middleware: %v", err)
	}
	log.Println("✓ Auth middleware created")

	mux := http.NewServeMux()
	mux.Handle("/", midd.Handler(http.HandlerFunc(pingHandler)))
	mux.Handle("/ping", midd.Handler(http.HandlerFunc(pingHandler)))

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
		log.Fatalf("Failed to create client private key: %v", err)
	}

	clientWallet, err := exampleWallet.NewExtendedProtoWallet(cPrivKey)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("✓ Client wallet created")
	log.Println("\n📡 STEP 1: Sending non general request to /.well-known/auth endpoint")
	responseData, err := callInitialRequest(clientWallet)
	if err != nil {
		log.Fatalf("Failed to call initial request: %v", err)
	}

	log.Println("✓ Auth completed")

	log.Println("\n📡 STEP 2: Sending general request to test authorization")
	callPingEndpoint(clientWallet, responseData)
	log.Println("✓ General request completed")

	time.Sleep(2 * time.Second)
	log.Println("\n✅ Demo completed successfully")
}

// pingHandler handles the ping requests
func pingHandler(w http.ResponseWriter, r *http.Request) {
	identityKey, ok := middleware.GetIdentityFromContext(r.Context())
	if !ok {
		log.Printf("Warning: No identity key in context")
	} else {
		log.Printf("Request from identity: %s", identityKey)
	}
	_, err := w.Write([]byte("Pong!"))
	if err != nil {
		log.Printf("Error writing ping response: %v", err)
	}
}

// callInitialRequest sends a request to the /.well-known/auth endpoint
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

	log.Println("Response from server: ", resp.String())

	log.Println("🔑 Response Headers:")
	for key, value := range resp.Header() {
		lowerKey := strings.ToLower(key)
		if strings.Contains(lowerKey, "x-bsv-auth") {
			log.Println(lowerKey, strings.Join(value, ", "))
		}
	}

	return &result, nil
}

// callPingEndpoint sends a request to the /ping endpoint
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

	log.Println("🔑 Request headers")
	for key, value := range headers {
		log.Println(key, value)
	}

	client := resty.New()
	resp, err := client.R().
		SetHeaders(headers).
		Get(url)

	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}

	log.Printf("Response from server: %s", resp.String())

	log.Println("🔑 Response Headers:")
	for key, value := range resp.Header() {
		lowerKey := strings.ToLower(key)
		if strings.Contains(lowerKey, "x-bsv-auth") {
			log.Println(lowerKey, strings.Join(value, ", "))
		}
	}

	if resp.IsError() {
		log.Printf("Warning: Received non-success status from /ping: %d", resp.StatusCode())
	}
}
