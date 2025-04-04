package payment

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
	fixtures "github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet/test"
	"github.com/4chain-ag/go-bsv-middleware/pkg/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func addIdentityToContext(r *http.Request, identityKey string) *http.Request {
	ctx := context.WithValue(r.Context(), transport.IdentityKey, identityKey)
	return r.WithContext(ctx)
}

// mockWalletSetup ensures the mock wallet's verifyNonce will return true for our test
// We do this by first calling createNonce on the wallet with our intended nonce
// This introduces it into the wallet's internal valid nonces map
func mockWalletSetup(t *testing.T, w wallet.WalletInterface, expectedNonce string) {
	nonce, err := w.CreateNonce(context.Background())
	require.NoError(t, err)

	valid, err := w.VerifyNonce(context.Background(), nonce)
	require.NoError(t, err)
	require.True(t, valid, "CreateNonce should create a valid nonce")

	valid, err = w.VerifyNonce(context.Background(), expectedNonce)
	require.NoError(t, err)
	require.True(t, valid, "Mock wallet should recognize MockNonce as valid")
}

func TestNewMiddleware(t *testing.T) {
	t.Run("Returns error with no wallet", func(t *testing.T) {
		//given
		options := Options{}

		//when
		_, err := New(options)

		//then
		assert.Error(t, err)
		assert.Equal(t, ErrNoWallet, err)
	})

	t.Run("Creates middleware with valid options", func(t *testing.T) {
		//given
		mockWallet := wallet.NewMockPaymentWallet()
		options := Options{
			Wallet: mockWallet,
		}

		//when
		middleware, err := New(options)

		//then
		assert.NoError(t, err)
		assert.NotNil(t, middleware)
	})
}

func TestMiddleware_Handler_MissingAuthContext(t *testing.T) {
	//given
	mockWallet := wallet.NewMockPaymentWallet()
	middleware, err := New(Options{
		Wallet: mockWallet,
	})
	require.NoError(t, err)

	var handlerCalled bool
	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	//when
	handler.ServeHTTP(w, req)

	//then
	assert.False(t, handlerCalled)
	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var resp map[string]any
	err = json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)

	assert.Equal(t, ErrCodeServerMisconfigured, resp["code"])
}

func TestMiddleware_Handler_FreeAccess(t *testing.T) {
	mockWallet := wallet.NewMockPaymentWallet()
	middleware, err := New(Options{
		Wallet: mockWallet,
		CalculateRequestPrice: func(r *http.Request) (int, error) {
			return 0, nil
		},
	})
	require.NoError(t, err)

	var handlerCalled bool
	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true

		info, ok := GetPaymentInfoFromContext(r.Context())
		assert.True(t, ok)
		assert.NotNil(t, info)
		assert.Equal(t, 0, info.SatoshisPaid)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req = addIdentityToContext(req, "test-identity-key")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.True(t, handlerCalled)
}

func TestMiddleware_Handler_PaymentRequired(t *testing.T) {
	//given
	mockWallet := wallet.NewMockPaymentWallet()
	middleware, err := New(Options{
		Wallet: mockWallet,
		CalculateRequestPrice: func(r *http.Request) (int, error) {
			return 100, nil
		},
	})
	require.NoError(t, err)

	var handlerCalled bool
	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req = addIdentityToContext(req, "test-identity-key")
	w := httptest.NewRecorder()

	//when
	handler.ServeHTTP(w, req)

	//then
	assert.False(t, handlerCalled)
	assert.Equal(t, http.StatusPaymentRequired, w.Code)

	var terms PaymentTerms
	err = json.NewDecoder(w.Body).Decode(&terms)
	require.NoError(t, err)

	assert.Equal(t, NetworkBSV, terms.Network)
	assert.Equal(t, PaymentVersion, terms.Version)
	assert.Equal(t, 100, terms.SatoshisRequired)
	assert.NotEmpty(t, terms.DerivationPrefix)
}

// TestMiddleware_Handler_InvalidPaymentData tests handling of malformed payment data
func TestMiddleware_Handler_InvalidPaymentData(t *testing.T) {
	//given
	mockWallet := wallet.NewMockPaymentWallet()
	middleware, err := New(Options{
		Wallet: mockWallet,
	})
	require.NoError(t, err)

	var handlerCalled bool
	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	}))

	// Invalid JSON
	req := httptest.NewRequest("GET", "/", nil)
	req = addIdentityToContext(req, "test-identity-key")
	req.Header.Set(HeaderPayment, "invalid-json-data")

	w := httptest.NewRecorder()

	//when
	handler.ServeHTTP(w, req)

	//then
	assert.False(t, handlerCalled)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]any
	err = json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)

	assert.Equal(t, ErrCodeMalformedPayment, resp["code"])
}

// TestCases for verifying payment processing
func TestMiddleware_Handler_ProcessPayment(t *testing.T) {
	t.Run("successful payment", func(t *testing.T) {
		//given
		mockWallet := wallet.NewMockPaymentWallet()

		mockWalletSetup(t, mockWallet, fixtures.MockNonce)

		mockWallet.SetInternalizeActionResult(wallet.InternalizeActionResult{
			Accepted: true,
		})

		middleware, err := New(Options{
			Wallet: mockWallet,
			CalculateRequestPrice: func(r *http.Request) (int, error) {
				return 100, nil
			},
		})
		require.NoError(t, err)

		var handlerCalled bool
		handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true

			info, ok := GetPaymentInfoFromContext(r.Context())
			assert.True(t, ok)
			assert.NotNil(t, info)
			assert.Equal(t, 100, info.SatoshisPaid)
			assert.True(t, info.Accepted)
		}))

		paymentData := Payment{
			ModeID:           "bsv-direct",
			DerivationPrefix: fixtures.MockNonce,
			DerivationSuffix: "test-suffix",
			Transaction:      []byte{1, 2, 3, 4},
		}
		paymentJSON, err := json.Marshal(paymentData)
		require.NoError(t, err)

		req := httptest.NewRequest("GET", "/", nil)
		req = addIdentityToContext(req, "test-identity-key")
		req.Header.Set(HeaderPayment, string(paymentJSON))

		w := httptest.NewRecorder()

		//when
		handler.ServeHTTP(w, req)

		//then
		assert.True(t, handlerCalled)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "100", w.Header().Get(HeaderSatoshisPaid))

		assert.True(t, mockWallet.InternalizeActionCalled)
		require.NotEmpty(t, mockWallet.InternalizeActionArgs.Outputs)
		require.NotNil(t, mockWallet.InternalizeActionArgs.Outputs[0].PaymentRemittance)
		assert.Equal(t, fixtures.MockNonce, mockWallet.InternalizeActionArgs.Outputs[0].PaymentRemittance.DerivationPrefix)
		assert.Equal(t, "test-suffix", mockWallet.InternalizeActionArgs.Outputs[0].PaymentRemittance.DerivationSuffix)
		assert.Equal(t, "test-identity-key", mockWallet.InternalizeActionArgs.Outputs[0].PaymentRemittance.SenderIdentityKey)
	})

	t.Run("wallet returns error", func(t *testing.T) {
		//given
		expectedError := errors.New("payment validation failed")
		mockWallet := wallet.NewMockPaymentWallet()

		mockWalletSetup(t, mockWallet, fixtures.MockNonce)

		mockWallet.SetInternalizeActionError(expectedError)

		middleware, err := New(Options{
			Wallet: mockWallet,
		})
		require.NoError(t, err)

		var handlerCalled bool
		handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
		}))

		paymentData := Payment{
			ModeID:           "bsv-direct",
			DerivationPrefix: fixtures.MockNonce,
			DerivationSuffix: "test-suffix",
			Transaction:      []byte{1, 2, 3, 4},
		}
		paymentJSON, err := json.Marshal(paymentData)
		require.NoError(t, err)

		req := httptest.NewRequest("GET", "/", nil)
		req = addIdentityToContext(req, "test-identity-key")
		req.Header.Set(HeaderPayment, string(paymentJSON))

		w := httptest.NewRecorder()

		//when
		handler.ServeHTTP(w, req)

		//then
		assert.False(t, handlerCalled)
		assert.Equal(t, http.StatusBadRequest, w.Code)

		var resp map[string]any
		err = json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)

		assert.Equal(t, ErrCodePaymentFailed, resp["code"])
		assert.Contains(t, resp["description"].(string), expectedError.Error())
	})
}
