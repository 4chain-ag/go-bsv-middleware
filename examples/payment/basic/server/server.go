package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/4chain-ag/go-bsv-middleware/pkg/middleware/auth"
	"github.com/4chain-ag/go-bsv-middleware/pkg/middleware/payment"
	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	paymentWallet := wallet.NewMockPaymentWallet()
	authMiddleware := auth.New(auth.Config{
		AllowUnauthenticated: false,
		Logger:               logger,
		Wallet:               paymentWallet,
	})

	paymentMiddleware, err := payment.New(payment.Options{
		Wallet: paymentWallet,
		CalculateRequestPrice: func(r *http.Request) (int, error) {
			switch r.URL.Path {
			case "/info":
				return 0, nil
			case "/premium":
				return 10, nil
			default:
				return 5, nil
			}
		},
	})
	if err != nil {
		logger.Error("middleware setup failed", slog.String("error", err.Error()))
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/info", infoHandler)
	mux.HandleFunc("/premium", premiumHandler)

	handler := authMiddleware.Handler(paymentMiddleware.Handler(mux))

	srv := &http.Server{
		Addr:    ":8080",
		Handler: handler,
	}

	go func() {
		logger.Info("server listening", slog.String("addr", srv.Addr))
		logger.Info("/.well-known/auth")
		logger.Info("/info (auth only)")
		logger.Info("/premium (paid)")
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server error", slog.Any("error", err))
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
}

func infoHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, err := w.Write([]byte(`{"name":"BSV Payment API","version":"1.0","type":"free"}`))
	if err != nil {
		fmt.Println("Error writing response:", err)
		return
	}
}

func premiumHandler(w http.ResponseWriter, r *http.Request) {
	info, ok := payment.GetPaymentInfoFromContext(r.Context())
	w.Header().Set("Content-Type", "application/json")

	if ok && info.SatoshisPaid > 0 {
		_, err := w.Write([]byte(`{"name":"BSV Payment API","version":"1.0","type":"premium","paid":true,"satoshis": ` + fmt.Sprintf("%d", info.SatoshisPaid) + `}`))
		if err != nil {
			fmt.Println("Error writing response:", err)
			return
		}
		return
	}

	_, err := w.Write([]byte(`{"name":"BSV Payment API","version":"1.0","type":"premium","paid":false}`))
	if err != nil {
		fmt.Println("Error writing response:", err)
		return
	}
}
