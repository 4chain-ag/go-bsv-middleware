package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/4chain-ag/go-bsv-middleware/pkg/utils"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/4chain-ag/go-bsv-middleware/pkg/middleware/payment"
	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
	walletFixtures "github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet/test"
	"github.com/4chain-ag/go-bsv-middleware/pkg/transport"
)

func main() {
	fmt.Println("BSV Payment Client - Demo")

	mockWallet := wallet.NewMockWallet(true, &walletFixtures.ClientIdentityKey, walletFixtures.ClientNonces...)
	fmt.Println("✓ Client mockWallet created")

	time.Sleep(1 * time.Second)

	fmt.Println("\n📡 STEP 1: AUTHENTICATION")
	auth := authenticate(mockWallet)
	fmt.Println("✓ Auth complete")

	fmt.Println("\n🔍 STEP 2: ACCESS FREE ENDPOINT")
	callFree(mockWallet, auth)
	fmt.Println("✓ Free endpoint OK")

	fmt.Println("\n💸 STEP 3: REQUEST PREMIUM (no mockPayment)")
	terms := requestPremium(mockWallet, auth)
	fmt.Printf("✓ 402 received: %d satoshis required\n", terms.SatoshisRequired)

	fmt.Println("\n💰 STEP 4: CREATE PAYMENT")
	mockPayment := createMockPayment(terms)
	fmt.Println("✓ Payment prepared")

	fmt.Println("\n💳 STEP 5: ACCESS PREMIUM (with mockPayment)")
	payPremium(mockWallet, auth, mockPayment)
	fmt.Println("✓ Premium content received")
}

func authenticate(wallet wallet.WalletInterface) *transport.AuthMessage {
	req := utils.PrepareInitialRequestBody(wallet)
	data, err := json.Marshal(req)
	if err != nil {
		log.Fatalf("failed to marshal auth request: %s", err)
		return nil
	}

	httpReq, err := http.NewRequest("POST", "http://localhost:8080/.well-known/auth", bytes.NewBuffer(data))
	if err != nil {
		log.Fatalf("failed to create auth request: %s", err)
		return nil
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		log.Fatal(err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Fatalf("failed to close response body: %s\n", err)
		}
	}(resp.Body)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("failed to read auth response: %s", err)
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("auth failed: %s", string(body))
	}

	var result *transport.AuthMessage
	err = json.Unmarshal(body, &result)
	if err != nil {
		log.Fatalf("failed to unmarshal auth response: %s", err)
		return nil
	}
	return result
}

func callFree(wallet wallet.WalletInterface, auth *transport.AuthMessage) {
	httpReq, err := http.NewRequest("GET", "http://localhost:8080/info", nil)
	if err != nil {
		log.Fatalf("failed to create auth request: %s", err)
		return
	}
	utils.PreparePingRequest(httpReq, wallet, auth)

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		log.Fatal(err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Fatalf("failed to unmarshal payment terms: %s", err)
		}
	}(resp.Body)

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("← HTTP %d: %s\n", resp.StatusCode, string(body))
}

func requestPremium(wallet wallet.WalletInterface, auth *transport.AuthMessage) *payment.PaymentTerms {
	httpReq, _ := http.NewRequest("GET", "http://localhost:8080/premium", nil)
	utils.PreparePingRequest(httpReq, wallet, auth)

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		log.Fatal(err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Fatalf("failed to unmarshal payment terms: %s", err)
		}
	}(resp.Body)

	if resp.StatusCode != http.StatusPaymentRequired {
		log.Fatalf("expected 402, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	var terms payment.PaymentTerms
	err = json.Unmarshal(body, &terms)
	if err != nil {
		log.Fatalf("failed to unmarshal payment terms: %s", err)
		return nil
	}
	return &terms
}

func createMockPayment(terms *payment.PaymentTerms) *payment.Payment {
	suffix := fmt.Sprintf("client-%d", time.Now().Unix())
	mockTx := []byte{0x01, 0x02, 0x03, 0x04}

	return &payment.Payment{
		ModeID:           "bsv-direct",
		DerivationPrefix: terms.DerivationPrefix,
		DerivationSuffix: suffix,
		Transaction:      mockTx,
	}
}

func payPremium(wallet wallet.WalletInterface, auth *transport.AuthMessage, pmt *payment.Payment) {
	httpReq, _ := http.NewRequest("GET", "http://localhost:8080/premium", nil)
	utils.PreparePingRequest(httpReq, wallet, auth)

	data, _ := json.Marshal(pmt)
	httpReq.Header.Set("X-BSV-Payment", string(data))

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		log.Fatal(err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Fatalf("failed to close response body: %s\n", err)
		}
	}(resp.Body)

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("← HTTP %d: %s\n", resp.StatusCode, string(body))

	if sat := resp.Header.Get("X-BSV-Payment-Satoshis-Paid"); sat != "" {
		fmt.Printf("← Confirmed: %s satoshis paid\n", sat)
	}
}
