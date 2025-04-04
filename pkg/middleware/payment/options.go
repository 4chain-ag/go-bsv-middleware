package payment

import (
	"net/http"

	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
)

const (
	defaultPrice = 100
)

// Options configures the payment middleware
type Options struct {
	// Wallet is used for payment processing operations
	Wallet wallet.PaymentInterface

	// CalculateRequestPrice determines the cost in satoshis for a request
	CalculateRequestPrice func(r *http.Request) (int, error)
}

// DefaultPriceFunc returns a basic pricing function that applies a flat rate
func DefaultPriceFunc(r *http.Request) (int, error) {
	return defaultPrice, nil
}
