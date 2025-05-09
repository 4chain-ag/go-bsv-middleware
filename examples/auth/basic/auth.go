package main

import (
	"context"
	"fmt"
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

	fmt.Println("✓ Server wallet created")

	opts := middleware.Config{
		AllowUnauthenticated: false,
		Logger:               logger,
		Wallet:               serverWallet,
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
	fmt.Println("✓ Client wallet created")

	fmt.Println("\n📡 STEP 1: Sending non general request to /.well-known/auth endpoint")
	responseData := callInitialRequest(clientWallet)
	fmt.Println("✓ Auth completed")

	fmt.Println("\n📡 STEP 2: Sending general request to test authorization")
	callPingEndpoint(clientWallet, responseData)
	fmt.Println("✓ General request completed")

	time.Sleep(2 * time.Second)
	fmt.Println("\n✅ Demo completed successfully")
}

// HTTP handler for ping requests
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
