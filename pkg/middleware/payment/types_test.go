package payment

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGetPaymentInfoFromContext(t *testing.T) {
	t.Run("Returns nil when no payment info in context", func(t *testing.T) {
		//given
		ctx := context.Background()

		//when
		info, ok := GetPaymentInfoFromContext(ctx)

		//then
		assert.False(t, ok)
		assert.Nil(t, info)
	})

	t.Run("Returns payment info when in context", func(t *testing.T) {
		//given
		expectedInfo := &PaymentInfo{
			SatoshisPaid:  100,
			Accepted:      true,
			TransactionID: "tx-1234",
		}

		ctx := context.WithValue(context.Background(), PaymentKey, expectedInfo)

		//when
		info, ok := GetPaymentInfoFromContext(ctx)

		//then
		assert.True(t, ok)
		assert.Equal(t, expectedInfo, info)
	})
}

func TestNewPaymentTerms(t *testing.T) {
	//given
	price := 250
	prefix := "test-prefix"
	url := "https://example.com/api/resource"

	//when
	terms := NewPaymentTerms(price, prefix, url)

	//then
	assert.Equal(t, NetworkBSV, terms.Network)
	assert.Equal(t, PaymentVersion, terms.Version)
	assert.Greater(t, terms.CreationTimestamp, int64(0))
	assert.Greater(t, terms.ExpirationTimestamp, terms.CreationTimestamp)
	assert.Equal(t, url, terms.PaymentURL)
	assert.Equal(t, prefix, terms.DerivationPrefix)
	assert.Equal(t, price, terms.SatoshisRequired)

	expectedExpiration := time.Now().Add(15 * time.Minute).Unix()
	assert.InDelta(t, expectedExpiration, terms.ExpirationTimestamp, 5)

	assert.Contains(t, terms.Modes, "bsv-direct")
	assert.Equal(t, "Direct BSV payment", terms.Modes["bsv-direct"].Description)
	assert.Equal(t, price, terms.Modes["bsv-direct"].Requirements["satoshis"])
}
