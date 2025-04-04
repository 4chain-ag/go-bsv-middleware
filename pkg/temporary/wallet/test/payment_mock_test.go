package wallet_test

import (
	"context"
	"errors"
	"testing"

	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
	"github.com/stretchr/testify/assert"
)

func TestMockPaymentWallet(t *testing.T) {
	t.Run("Implements PaymentInterface", func(t *testing.T) {
		var _ wallet.PaymentInterface = &wallet.MockPaymentWallet{}
	})

	t.Run("Records InternalizeAction arguments", func(t *testing.T) {
		mock := wallet.NewMockPaymentWallet()
		args := wallet.InternalizeActionArgs{
			Tx: []byte{1, 2, 3},
			Outputs: []wallet.InternalizeOutput{
				{
					OutputIndex: 0,
					Protocol:    "wallet payment",
					PaymentRemittance: &wallet.PaymentRemittance{
						DerivationPrefix:  "prefix",
						DerivationSuffix:  "suffix",
						SenderIdentityKey: "sender",
					},
				},
			},
			Description: "Test payment",
		}

		result, err := mock.InternalizeAction(context.Background(), args)

		assert.NoError(t, err)
		assert.True(t, result.Accepted)
		assert.True(t, mock.InternalizeActionCalled)
		assert.Equal(t, args, mock.InternalizeActionArgs)
	})

	t.Run("Returns configured error", func(t *testing.T) {
		mock := wallet.NewMockPaymentWallet()
		expectedErr := errors.New("payment error")
		mock.SetInternalizeActionError(expectedErr)

		_, err := mock.InternalizeAction(context.Background(), wallet.InternalizeActionArgs{})

		assert.Error(t, err)
		assert.Equal(t, expectedErr, err)
	})

	t.Run("Returns configured result", func(t *testing.T) {
		mock := wallet.NewMockPaymentWallet()
		expectedResult := wallet.InternalizeActionResult{Accepted: false}
		mock.SetInternalizeActionResult(expectedResult)

		result, err := mock.InternalizeAction(context.Background(), wallet.InternalizeActionArgs{})

		assert.NoError(t, err)
		assert.Equal(t, expectedResult, result)
	})
}
