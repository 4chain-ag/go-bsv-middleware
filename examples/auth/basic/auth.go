package main

import (
	"fmt"
	"github.com/go-resty/resty/v2"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/4chain-ag/go-bsv-middleware/pkg/middleware/auth"
	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
	walletFixtures "github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet/test"
	"github.com/4chain-ag/go-bsv-middleware/pkg/test/mocks"
	"github.com/4chain-ag/go-bsv-middleware/pkg/transport"
)

func main() {
	fmt.Println("BSV Auth middleware - Demo")
	logHandler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := slog.New(logHandler)

	serverMockedWallet := wallet.NewMockWallet(true, nil, walletFixtures.DefaultNonces...)
	fmt.Println("✓ Server mockWallet created")

	opts := auth.Config{
		AllowUnauthenticated: false,
		Logger:               logger,
		Wallet:               serverMockedWallet,
	}
	middleware := auth.New(opts)

	fmt.Println("✓ Auth middleware created")

	mux := http.NewServeMux()
	mux.Handle("/", middleware.Handler(http.HandlerFunc(pingHandler)))
	mux.Handle("/ping", middleware.Handler(http.HandlerFunc(pingHandler)))

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
	time.Sleep(1 * time.Second)

	fmt.Println("✓ HTTP Server started")

	mockedWallet := wallet.NewMockWallet(true, &walletFixtures.ClientIdentityKey, walletFixtures.ClientNonces...)
	fmt.Println("✓ Client mockWallet created")

	fmt.Println("\n📡 STEP 1: Sending non general request to /.well-known/auth endpoint")
	responseData := callInitialRequest(mockedWallet)
	fmt.Println("✓ Auth completed")

	fmt.Println("\n📡 STEP 2: Sending general request to test authorization")
	callPingEndpoint(mockedWallet, responseData)
	fmt.Println("✓ General request completed")
}

func pingHandler(w http.ResponseWriter, r *http.Request) {
	_, err := w.Write([]byte("Pong!"))
	if err != nil {
		log.Printf("Error writing ping response: %v", err)
	}
}

func callInitialRequest(mockedWallet wallet.WalletInterface) *transport.AuthMessage {
	requestData := mocks.PrepareInitialRequestBody(mockedWallet)
	url := "http://localhost:8080/.well-known/auth"

	client := resty.New()
	var result transport.AuthMessage
	var errMsg interface{}

	resp, err := client.R().
		SetHeader("Content-Type", "application/json").
		SetBody(requestData).
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

func callPingEndpoint(mockedWallet wallet.WalletInterface, response *transport.AuthMessage) {
	url := "http://localhost:8080/ping"
	method := "GET"

	headers, err := mocks.PrepareGeneralRequestHeaders(mockedWallet, response, "/ping", method)
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
