package wallet

import "context"

// WalletInterface defines the core functionality needed for authentication
type WalletInterface interface { //nolint:revive // WalletInterface will be adopted from GO-SDK in the future.
	// GetPublicKey returns a public key
	GetPublicKey(ctx context.Context, options GetPublicKeyOptions) (string, error)

	// CreateSignature signs data with specific protocol/key IDs
	CreateSignature(ctx context.Context, data []byte, protocolID any, keyID string, counterparty string) ([]byte, error)

	// VerifySignature verifies a signature
	VerifySignature(ctx context.Context, data []byte, signature []byte, protocolID any, keyID string, counterparty string) (bool, error)

	// CreateNonce creates a nonce for challenge-response authentication
	CreateNonce(ctx context.Context) (string, error)

	// VerifyNonce verifies a nonce that was previously created
	VerifyNonce(ctx context.Context, nonce string) (bool, error)

	// ListCertificates is a stub for future certificate functionality
	ListCertificates(ctx context.Context, certifiers []string, types []string) ([]Certificate, error)

	// ProveCertificate is a stub for future certificate functionality
	ProveCertificate(ctx context.Context, certificate Certificate, verifier string, fieldsToReveal []string) (map[string]string, error)
}
