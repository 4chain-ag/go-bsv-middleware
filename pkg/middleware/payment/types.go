package payment

import (
	"context"
	"time"
)

// PaymentMode represents a payment method option in the DPP protocol
type PaymentMode struct { //nolint: revive // Ignore that struct starts with package name
	// ModeID is the identifier for the payment mode
	ModeID string `json:"modeId"`
	// Description provides a human-readable description of the payment mode
	Description string `json:"description"`
	// Requirements specifies the requirements for this payment mode
	Requirements map[string]any `json:"requirements"`
}

// Merchant represents information about the merchant/recipient
type Merchant struct {
	// Name is the name of the beneficiary
	Name string `json:"name"`
	// Description provides a description of the beneficiary
	Email string `json:"email,omitempty"`
	// Email is the email address of the beneficiary
	PaymentReference string `json:"paymentReference,omitempty"`
	// PaymentReference is a reference for the payment
	ExtendedData map[string]any `json:"extendedData,omitempty"`
}

// PaymentTerms represents the DPP PaymentTerms message sent to the client when payment is required
type PaymentTerms struct { //nolint: revive // Ignore that struct starts with package name
	// Network is the network identifier (e.g., Bitcoin SV)
	Network string `json:"network"`
	// Version is the version of the DPP protocol
	Version string `json:"version"`
	// CreationTimestamp is the timestamp when the payment terms were created
	CreationTimestamp int64 `json:"creationTimestamp"`
	// ExpirationTimestamp is the timestamp when the payment terms expire
	ExpirationTimestamp int64 `json:"expirationTimestamp,omitempty"`
	// Memo is an optional message to the payer
	Memo string `json:"memo,omitempty"`
	// PaymentURL is the URL where the payment should be made
	PaymentURL string `json:"paymentUrl"`
	// Merchant is the recipient of the payment
	Merchant *Merchant `json:"beneficiary,omitempty"`
	// PaymentReference is a reference for the payment
	Modes map[string]PaymentMode `json:"modes"`
	// DerivationPrefix is the prefix for the payment address
	DerivationPrefix string `json:"derivationPrefix"`
	// DerivationSuffix is the suffix for the payment address
	SatoshisRequired int `json:"satoshisRequired"`
}

// Payment represents the client payment data sent by the payer
type Payment struct {
	// ModeID is the identifier for the payment mode
	ModeID string `json:"modeId"`
	// DerivationPrefix is the prefix for the payment address
	DerivationPrefix string `json:"derivationPrefix"`
	// DerivationSuffix is the suffix for the payment address
	DerivationSuffix string `json:"derivationSuffix"`
	// Transaction is the payment transaction data
	Transaction []byte `json:"transaction"`
}

// PaymentACK represents the payment acknowledgment sent back to the client
type PaymentACK struct { //nolint: revive // Ignore that struct starts with package name
	// ModeID is the identifier for the payment mode
	ModeID string `json:"modeId"`
	// Accepted indicates whether the payment was accepted
	Accepted bool `json:"accepted"`
	// SatoshisPaid is the amount paid in satoshis
	SatoshisPaid int `json:"satoshisPaid"`
	// TransactionID is the identifier for the payment transaction
	TransactionID string `json:"transactionId,omitempty"`
}

// PaymentInfo holds information about a processed payment stored in the request context
type PaymentInfo struct { //nolint: revive // Ignore that struct starts with package name
	// SatoshisPaid is the amount paid in satoshis
	SatoshisPaid int
	// Accepted indicates whether the payment was accepted
	Accepted bool
	// Tx is the payment transaction data
	Tx []byte
	// TransactionID is the identifier for the payment transaction
	TransactionID string
}

// contextKey is a private type for context keys
type contextKey string

// PaymentKey is the context key for payment info
const PaymentKey contextKey = "payment_info"

// NewPaymentTerms creates a PaymentTerms structure for the given request
func NewPaymentTerms(price int, derivationPrefix, requestURL string) PaymentTerms {
	now := time.Now()

	// standard BSV payment mode
	bsvMode := PaymentMode{
		ModeID:      "bsv-direct",
		Description: "Direct BSV payment",
		Requirements: map[string]interface{}{
			"satoshis": price,
		},
	}

	return PaymentTerms{
		Network:             NetworkBSV,
		Version:             PaymentVersion,
		CreationTimestamp:   now.Unix(),
		ExpirationTimestamp: now.Add(15 * time.Minute).Unix(),
		PaymentURL:          requestURL,
		Memo:                "Payment required to access this resource",
		Modes:               map[string]PaymentMode{"bsv-direct": bsvMode},
		DerivationPrefix:    derivationPrefix,
		SatoshisRequired:    price,
	}
}

// GetPaymentInfoFromContext retrieves payment info from context
func GetPaymentInfoFromContext(ctx context.Context) (*PaymentInfo, bool) {
	info, ok := ctx.Value(PaymentKey).(*PaymentInfo)
	return info, ok
}
