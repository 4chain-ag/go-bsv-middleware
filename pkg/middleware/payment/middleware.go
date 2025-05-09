package payment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/interfaces"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/logging"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/middleware/auth"
	sdkUtils "github.com/bsv-blockchain/go-sdk/auth/utils"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// Middleware is the payment middleware handler that implements Direct Payment Protocol (DPP) for HTTP-based micropayments
type Middleware struct {
	logger                *slog.Logger
	wallet                interfaces.Payment
	calculateRequestPrice func(r *http.Request) (int, error)
}

// New creates a new payment middleware
func New(opts Options) (*Middleware, error) {
	if opts.Wallet == nil {
		return nil, ErrNoWallet
	}

	if opts.CalculateRequestPrice == nil {
		opts.CalculateRequestPrice = DefaultPriceFunc
	}

	logger := logging.Child(nil, "payment-middleware")

	return &Middleware{
		logger:                logger,
		wallet:                opts.Wallet,
		calculateRequestPrice: opts.CalculateRequestPrice,
	}, nil
}

// Handler returns a middleware handler function that processes payments
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identityKey, ok := auth.GetIdentityFromContext(r.Context())
		if !ok {
			respondWithError(w, http.StatusInternalServerError, ErrCodeServerMisconfigured,
				ErrAuthMiddlewareMissing.Error())
			return
		}

		price, err := m.calculateRequestPrice(r)
		if err != nil {
			m.logger.Error("Error calculating request price", slog.String("error", err.Error()))
			respondWithError(w, http.StatusInternalServerError, ErrCodePaymentInternal,
				fmt.Sprintf("Error calculating request price: %s", err.Error()))
			return
		}

		if price == 0 {
			proceedWithoutPayment(w, r, next)
			return
		}

		paymentData, err := extractPaymentData(r)
		if err != nil {
			m.logger.Error("Error extracting payment data", slog.String("error", err.Error()))
			respondWithError(w, http.StatusBadRequest, ErrCodeMalformedPayment, err.Error())
			return
		}

		if paymentData == nil {
			requestPayment(w, r, m.wallet, price)
			return
		}

		paymentInfo, err := processPayment(r.Context(), m.wallet, paymentData, identityKey, price)
		if err != nil {
			m.logger.Error("Error processing payment", slog.String("error", err.Error()))
			respondWithError(w, http.StatusBadRequest, ErrCodePaymentFailed,
				fmt.Sprintf("Payment failed: %s", err.Error()))
			return
		}

		proceedWithSuccessfulPayment(w, r, next, paymentInfo)
	})
}

func proceedWithoutPayment(w http.ResponseWriter, r *http.Request, next http.Handler) {
	ctx := context.WithValue(r.Context(), PaymentKey, &PaymentInfo{SatoshisPaid: 0})
	next.ServeHTTP(w, r.WithContext(ctx))
}

func proceedWithSuccessfulPayment(w http.ResponseWriter, r *http.Request, next http.Handler, paymentInfo *PaymentInfo) {
	ctx := context.WithValue(r.Context(), PaymentKey, paymentInfo)
	sendPaymentAcknowledgment(w, paymentInfo)
	next.ServeHTTP(w, r.WithContext(ctx))
}

func extractPaymentData(r *http.Request) (*Payment, error) {
	paymentHeader := r.Header.Get(HeaderPayment)
	if paymentHeader == "" {
		return nil, nil
	}

	var payment Payment
	if err := json.Unmarshal([]byte(paymentHeader), &payment); err != nil {
		return nil, fmt.Errorf("invalid payment data format: %w", err)
	}

	return &payment, nil
}

func requestPayment(w http.ResponseWriter, r *http.Request, walletInstance interfaces.Payment, price int) {
	derivationPrefix, err := sdkUtils.CreateNonce(r.Context(), walletInstance, wallet.Counterparty{Type: wallet.CounterpartyTypeSelf})
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, ErrCodePaymentInternal,
			fmt.Sprintf("Error creating nonce: %s", err.Error()))
		return
	}

	terms := NewPaymentTerms(price, derivationPrefix, r.URL.String())

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusPaymentRequired)
	err = json.NewEncoder(w).Encode(terms)
	if err != nil {
		return
	}
}

func processPayment(
	ctx context.Context,
	walletInstance interfaces.Payment,
	paymentData *Payment,
	identityKey string,
	price int,
) (*PaymentInfo, error) {
	valid, err := sdkUtils.VerifyNonce(ctx, paymentData.DerivationPrefix, walletInstance, wallet.Counterparty{Type: wallet.CounterpartyTypeSelf})
	if err != nil {
		return nil, fmt.Errorf("error verifying nonce: %w", err)
	}

	if !valid {
		return nil, errors.New("invalid derivation prefix")
	}

	result, err := walletInstance.InternalizeAction(ctx, wallet.InternalizeActionArgs{
		Tx: paymentData.Transaction,
		Outputs: []wallet.InternalizeOutput{
			{
				OutputIndex: 0,
				Protocol:    "wallet payment",
				PaymentRemittance: &wallet.Payment{
					DerivationPrefix:  paymentData.DerivationPrefix,
					DerivationSuffix:  paymentData.DerivationSuffix,
					SenderIdentityKey: identityKey,
				},
			},
		},
		Description: "Payment for request",
	},
		identityKey,
	)

	if err != nil {
		return nil, fmt.Errorf("payment processing failed: %w", err)
	}

	var txid string
	if len(paymentData.Transaction) >= 4 {
		txid = fmt.Sprintf("tx-%x", paymentData.Transaction[:4])
	} else {
		txid = fmt.Sprintf("tx-%x", paymentData.Transaction)
	}

	return &PaymentInfo{
		SatoshisPaid:  price,
		Accepted:      result.Accepted,
		Tx:            paymentData.Transaction,
		TransactionID: txid,
	}, nil
}

func sendPaymentAcknowledgment(w http.ResponseWriter, paymentInfo *PaymentInfo) {
	w.Header().Set(HeaderSatoshisPaid, fmt.Sprintf("%d", paymentInfo.SatoshisPaid))
}

func respondWithError(w http.ResponseWriter, status int, code, message string, extraData ...map[string]any) {
	resp := map[string]any{
		"status":      "error",
		"code":        code,
		"description": message,
	}

	if len(extraData) > 0 {
		for k, v := range extraData[0] {
			resp[k] = v
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	err := json.NewEncoder(w).Encode(resp)
	if err != nil {
		return
	}
}
