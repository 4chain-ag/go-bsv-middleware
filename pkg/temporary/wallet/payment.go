package wallet

import "context"

// PaymentInterface extends the basic wallet interface with payment-specific methods.
type PaymentInterface interface {
	WalletInterface

	// InternalizeAction processes a received payment transaction
	InternalizeAction(ctx context.Context, args InternalizeActionArgs) (InternalizeActionResult, error)
}
