package payment

import (
	"context"

	"github.com/bsv-blockchain/go-bsv-middleware/test/mocks"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// !!THIS MOCK WILL BE MOVED INTO THE MOCKS PACKAGE AFTER REPLACING INTERFACE WITH GO-SDK EQUIVALENTS!!

// MockPaymentWallet implements wallet.PaymentInterface for testing
type MockPaymentWallet struct {
	Wallet wallet.AuthOperations

	InternalizeActionCalled bool
	InternalizeActionArgs   wallet.InternalizeActionArgs
	InternalizeActionResult wallet.InternalizeActionResult
	InternalizeActionError  error
}

// NewMockPaymentWallet creates a new payment-capable mock wallet
func NewMockPaymentWallet(key *ec.PrivateKey) *MockPaymentWallet {
	return &MockPaymentWallet{
		Wallet: mocks.NewMockWallet(key),
		InternalizeActionResult: wallet.InternalizeActionResult{
			Accepted: true,
		},
	}
}

// InternalizeAction implements wallet.PaymentInterface
func (m *MockPaymentWallet) InternalizeAction(ctx context.Context, args wallet.InternalizeActionArgs) (wallet.InternalizeActionResult, error) {
	m.InternalizeActionCalled = true
	m.InternalizeActionArgs = args

	if m.InternalizeActionError != nil {
		return wallet.InternalizeActionResult{}, m.InternalizeActionError
	}

	return m.InternalizeActionResult, nil
}

// SetInternalizeActionError configures error response
func (m *MockPaymentWallet) SetInternalizeActionError(err error) {
	m.InternalizeActionError = err
}

// SetInternalizeActionResult configures result
func (m *MockPaymentWallet) SetInternalizeActionResult(result wallet.InternalizeActionResult) {
	m.InternalizeActionResult = result
}
