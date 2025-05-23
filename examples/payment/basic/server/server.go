package main

// import (
// 	"errors"
// 	"fmt"
// 	"log/slog"
// 	"net/http"
// 	"os"
// 	"os/signal"
// 	"syscall"

// 	wallet "github.com/bsv-blockchain/go-bsv-middleware-examples/example-wallet"
// 	"github.com/bsv-blockchain/go-bsv-middleware/pkg/middleware/auth"
// 	"github.com/bsv-blockchain/go-bsv-middleware/pkg/middleware/payment"
// 	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
// )

// const (
// 	serverPrivateKeyHex = "5a4d867377bd44eba1cecd0806c16f24e293f7e218c162b1177571edaeeaecef"
// 	clientPrivateKeyHex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
// 	serverPort          = ":8080"
// 	trustedCertifier    = "02certifieridentitykey00000000000000000000000000000000000000000000000"
// )

// func main() {
// 	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

// 	sPrivKey, err := ec.PrivateKeyFromHex(serverPrivateKeyHex)
// 	if err != nil {
// 		panic(err)
// 	}

// 	paymentWallet, err := wallet.NewExampleWallet(wallet.ExampleWalletArgs{
// 		Type:       wallet.ExampleWalletArgsTypePrivateKey,
// 		PrivateKey: sPrivKey,
// 	})
// 	if err != nil {
// 		logger.Error("create wallet failed", slog.String("error", err.Error()))
// 		os.Exit(1)
// 	}
// 	authMiddleware, err := auth.New(auth.Config{
// 		AllowUnauthenticated: false,
// 		Logger:               logger,
// 		Wallet:               paymentWallet,
// 	})
// 	if err != nil {
// 		logger.Error("create auth middleware failed", slog.String("error", err.Error()))
// 		os.Exit(1)
// 	}

// 	paymentMiddleware, err := payment.New(payment.Options{
// 		Wallet: paymentWallet,
// 		CalculateRequestPrice: func(r *http.Request) (int, error) {
// 			switch r.URL.Path {
// 			case "/info":
// 				return 0, nil
// 			case "/premium":
// 				return 10, nil
// 			default:
// 				return 5, nil
// 			}
// 		},
// 	})
// 	if err != nil {
// 		logger.Error("middleware setup failed", slog.String("error", err.Error()))
// 		os.Exit(1)
// 	}

// 	mux := http.NewServeMux()
// 	mux.HandleFunc("/info", infoHandler)
// 	mux.HandleFunc("/premium", premiumHandler)

// 	handler := authMiddleware.Handler(paymentMiddleware.Handler(mux))

// 	srv := &http.Server{
// 		Addr:    ":8080",
// 		Handler: handler,
// 	}

// 	go func() {
// 		logger.Info("server listening", slog.String("addr", srv.Addr))
// 		logger.Info("/.well-known/auth")
// 		logger.Info("/info (auth only)")
// 		logger.Info("/premium (paid)")
// 		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
// 			logger.Error("server error", slog.Any("error", err))
// 		}
// 	}()

// 	quit := make(chan os.Signal, 1)
// 	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
// 	<-quit
// }

// func infoHandler(w http.ResponseWriter, r *http.Request) {
// 	w.Header().Set("Content-Type", "application/json")
// 	_, err := w.Write([]byte(`{"name":"BSV Payment API","version":"1.0","type":"free"}`))
// 	if err != nil {
// 		fmt.Println("Error writing response:", err)
// 		return
// 	}
// }

// func premiumHandler(w http.ResponseWriter, r *http.Request) {
// 	info, ok := payment.GetPaymentInfoFromContext(r.Context())
// 	w.Header().Set("Content-Type", "application/json")

// 	if ok && info.SatoshisPaid > 0 {
// 		response := fmt.Sprintf(`{
//             "name": "BSV Payment API",
//             "version": "1.0",
//             "type": "premium",
//             "paid": true,
//             "satoshis": %d,
//             "status": "Payment accepted",
//             "txid": "%s"
//         }`, info.SatoshisPaid, info.TransactionID)

// 		_, err := w.Write([]byte(response))
// 		if err != nil {
// 			fmt.Println("Error writing response:", err)
// 			return
// 		}
// 		return
// 	}

// 	// NOTE: This code path is for demonstration only and won't actually execute
// 	// in normal operation because the payment middleware would intercept the request
// 	// with a 402 Payment Required response before reaching this handler
// 	response := `{
//         "name": "BSV Payment API",
//         "version": "1.0",
//         "type": "premium",
//         "paid": false,
//         "note": "This code path would normally not be reached - middleware would return 402 Payment Required"
//     }`

// 	_, err := w.Write([]byte(response))
// 	if err != nil {
// 		fmt.Println("Error writing response:", err)
// 		return
// 	}
// }
