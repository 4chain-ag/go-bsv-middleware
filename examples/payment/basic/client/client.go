package main

// import (
// 	"context"
// 	"encoding/json"
// 	"fmt"
// 	"log"
// 	"net/http"
// 	"time"

// 	exampleWallet "github.com/bsv-blockchain/go-bsv-middleware-examples/example-wallet"
// 	"github.com/bsv-blockchain/go-sdk/wallet"

// 	"github.com/bsv-blockchain/go-bsv-middleware/pkg/middleware/payment"
// 	"github.com/bsv-blockchain/go-bsv-middleware/pkg/utils"
// 	"github.com/bsv-blockchain/go-sdk/auth"

// 	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
// 	"github.com/go-resty/resty/v2"
// )

// const (
// 	serverPrivateKeyHex = "5a4d867377bd44eba1cecd0806c16f24e293f7e218c162b1177571edaeeaecef"
// 	clientPrivateKeyHex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
// 	serverPort          = ":8080"
// 	trustedCertifier    = "02certifieridentitykey00000000000000000000000000000000000000000000000"
// )

// // TODO: Check nonce validation mechanism in go-sdk
// func main() {
// 	fmt.Println("BSV Payment Client - Demo")

// 	sPrivKey, err := ec.PrivateKeyFromHex(clientPrivateKeyHex)
// 	if err != nil {
// 		panic(err)
// 	}

// 	mockWallet, err := exampleWallet.NewExampleWallet(exampleWallet.ExampleWalletArgs{
// 		Type:       exampleWallet.ExampleWalletArgsTypePrivateKey,
// 		PrivateKey: sPrivKey,
// 	})
// 	fmt.Println("✓ Client mockWallet created")

// 	time.Sleep(1 * time.Second)

// 	fmt.Println("\n📡 STEP 1: AUTHENTICATION")
// 	auth := authenticate(context.Background(), mockWallet)
// 	fmt.Println("✓ Auth complete")

// 	fmt.Println("\n🔍 STEP 2: ACCESS FREE ENDPOINT")
// 	callFree(context.Background(), mockWallet, auth)
// 	fmt.Println("✓ Free endpoint OK")

// 	fmt.Println("\n💸 STEP 3: REQUEST PREMIUM (no mockPayment)")
// 	terms := requestPremium(context.Background(), mockWallet, auth)
// 	fmt.Printf("✓ 402 received: %d satoshis required\n", terms.SatoshisRequired)

// 	fmt.Println("\n💰 STEP 4: CREATE PAYMENT")
// 	mockPayment := createMockPayment(terms)
// 	fmt.Println("✓ Payment prepared")

// 	fmt.Println("\n💳 STEP 5: ACCESS PREMIUM (with mockPayment)")
// 	payPremium(context.Background(), mockWallet, auth, mockPayment)
// 	fmt.Println("✓ Premium content received")
// }

// func authenticate(ctx context.Context, wallet wallet.Interface) *auth.AuthMessage {
// 	client := resty.New()

// 	reqBody := utils.PrepareInitialRequestBody(ctx, wallet)

// 	var result auth.AuthMessage
// 	var errMsg any

// 	resp, err := client.R().
// 		SetHeader("Content-Type", "application/json").
// 		SetBody(reqBody).
// 		SetResult(&result).
// 		SetError(&errMsg).
// 		Post("http://localhost:8080/.well-known/auth")

// 	if err != nil {
// 		log.Fatalf("failed to send auth request: %s", err)
// 		return nil
// 	}

// 	if resp.IsError() {
// 		log.Fatalf("auth failed: Status %d, Body: %s", resp.StatusCode(), resp.String())
// 		return nil
// 	}

// 	return &result
// }

// func callFree(ctx context.Context, wallet wallet.Interface, auth *auth.AuthMessage) {
// 	client := resty.New()
// 	url := "http://localhost:8080/info"

// 	requestData := utils.RequestData{
// 		Method: http.MethodGet,
// 		URL:    url,
// 	}

// 	modifiedAuth := *auth
// 	if modifiedAuth.InitialNonce == "" && modifiedAuth.Nonce != "" {
// 		modifiedAuth.InitialNonce = modifiedAuth.Nonce
// 	}

// 	headers, err := utils.PrepareGeneralRequestHeaders(ctx, wallet, auth, requestData)
// 	if err != nil {
// 		log.Fatalf("failed to prepare request headers for free endpoint: %s", err)
// 	}

// 	resp, err := client.R().
// 		SetHeaders(headers).
// 		Get(url)

// 	if err != nil {
// 		log.Fatalf("failed to call free endpoint: %s", err)
// 	}

// 	fmt.Printf("← HTTP %d: %s\n", resp.StatusCode(), resp.String())
// }

// func requestPremium(ctx context.Context, wallet wallet.Interface, auth *auth.AuthMessage) *payment.PaymentTerms {
// 	client := resty.New()
// 	url := "http://localhost:8080/premium"

// 	requestData := utils.RequestData{
// 		Method: http.MethodGet,
// 		URL:    url,
// 	}
// 	headers, err := utils.PrepareGeneralRequestHeaders(ctx, wallet, auth, requestData)
// 	if err != nil {
// 		log.Fatalf("failed to prepare request headers for premium request: %s", err)
// 		return nil
// 	}

// 	var terms payment.PaymentTerms
// 	var errMsg any

// 	resp, err := client.R().
// 		SetHeaders(headers).
// 		SetError(&errMsg).
// 		Get(url)

// 	if err != nil {
// 		log.Fatalf("failed to request premium endpoint: %s", err)
// 		return nil
// 	}

// 	if resp.StatusCode() != http.StatusPaymentRequired {
// 		log.Fatalf("expected status %d for premium request, got %d. Body: %s",
// 			http.StatusPaymentRequired, resp.StatusCode(), resp.String())
// 		return nil
// 	}

// 	// Manually unmarshal the expected 402 body
// 	err = json.Unmarshal(resp.Body(), &terms)
// 	if err != nil {
// 		log.Fatalf("failed to unmarshal payment terms (402 response): %s. Body: %s", err, resp.String())
// 		return nil
// 	}

// 	return &terms
// }

// func createMockPayment(terms *payment.PaymentTerms) *payment.Payment {
// 	suffix := fmt.Sprintf("client-%d", time.Now().Unix())
// 	// In a real scenario, you would construct a valid BSV transaction here
// 	// using the details from 'terms' (like outputs, amounts).
// 	mockTx := []byte{0x01, 0x02, 0x03, 0x04} // Placeholder transaction bytes

// 	return &payment.Payment{
// 		ModeID:           "bsv-direct",
// 		DerivationPrefix: terms.DerivationPrefix,
// 		DerivationSuffix: suffix,
// 		Transaction:      mockTx,
// 	}
// }

// func payPremium(ctx context.Context, wallet wallet.Interface, auth *auth.AuthMessage, pmt *payment.Payment) {
// 	client := resty.New()
// 	url := "http://localhost:8080/premium"

// 	requestData := utils.RequestData{
// 		Method: http.MethodGet,
// 		URL:    url,
// 	}
// 	generalHeaders, err := utils.PrepareGeneralRequestHeaders(ctx, wallet, auth, requestData)
// 	if err != nil {
// 		log.Fatalf("failed to prepare request headers for paying premium: %s", err)
// 	}

// 	paymentData, err := json.Marshal(pmt)
// 	if err != nil {
// 		log.Fatalf("failed to marshal payment data for header: %s", err)
// 	}

// 	var errMsg any

// 	resp, err := client.R().
// 		SetHeaders(generalHeaders).
// 		SetHeader("X-BSV-Payment", string(paymentData)).
// 		SetError(&errMsg).
// 		Get(url)

// 	if err != nil {
// 		log.Fatalf("failed to pay premium endpoint: %s", err)
// 	}

// 	fmt.Printf("← HTTP %d: %s\n", resp.StatusCode(), resp.String())

// 	if resp.IsError() {
// 		log.Printf("Warning: Received non-success status %d after payment.", resp.StatusCode())
// 	}

// 	if sat := resp.Header().Get("X-BSV-Payment-Satoshis-Paid"); sat != "" {
// 		fmt.Printf("← Confirmed: %s satoshis paid\n", sat)
// 	} else if resp.IsSuccess() {
// 		log.Printf("Warning: Payment request successful (Status %d), but 'X-BSV-Payment-Satoshis-Paid' header was missing or empty.", resp.StatusCode())
// 	}
// }
