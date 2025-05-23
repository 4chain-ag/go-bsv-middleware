package mocks

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/interfaces"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/mock"
)

// CreateServerMockWallet returns a mock wallet for server with predefined keys
func CreateServerMockWallet(key *ec.PrivateKey) wallet.Interface {
	return NewMockWallet(key, DefaultNonces...)
}

// CreateClientMockWallet returns a mock wallet for client with predefined nonces
func CreateClientMockWallet() interfaces.Wallet {
	key, err := ec.PrivateKeyFromHex(ClientPrivateKeyHex)
	if err != nil {
		panic(err)
	}
	return NewMockWallet(key, ClientNonces...)
}

// MockableWallet is a testify mock implementation for testing
type MockableWallet struct {
	mock.Mock
}

// NewMockableWallet creates a new instance of MockableWallet
func NewMockableWallet() *MockableWallet {
	return &MockableWallet{}
}

// Wallet is a simple implementation of interfaces.Wallet
type Wallet struct {
	keyDeriver  *wallet.KeyDeriver
	validNonces map[string]bool
	nonces      []string
}

// NewMockWallet creates a new mock wallet with given privateKey and nonces
func NewMockWallet(privateKey *ec.PrivateKey, nonces ...string) wallet.Interface {
	return &Wallet{
		validNonces: make(map[string]bool),
		nonces:      append([]string(nil), nonces...),
		keyDeriver:  wallet.NewKeyDeriver(privateKey),
	}
}

// MockableWallet methods - Key Operations

// GetPublicKey returns a mocked public key
func (m *MockableWallet) GetPublicKey(ctx context.Context, args wallet.GetPublicKeyArgs, originator string) (*wallet.GetPublicKeyResult, error) {
	if !isExpectedMockCall(m.ExpectedCalls, "GetPublicKey", args, originator) {
		return nil, errors.New("unexpected call to GetPublicKey")
	}
	call := m.Called(args, originator)
	return call.Get(0).(*wallet.GetPublicKeyResult), call.Error(1)
}

// Encrypt returns a mocked encryption result
func (m *MockableWallet) Encrypt(ctx context.Context, args wallet.EncryptArgs, originator string) (*wallet.EncryptResult, error) {
	if !isExpectedMockCall(m.ExpectedCalls, "Encrypt", args, originator) {
		return nil, errors.New("unexpected call to Encrypt")
	}
	call := m.Called(args, originator)
	return call.Get(0).(*wallet.EncryptResult), call.Error(1)
}

// Decrypt returns a mocked decryption result
func (m *MockableWallet) Decrypt(ctx context.Context, args wallet.DecryptArgs, originator string) (*wallet.DecryptResult, error) {
	if !isExpectedMockCall(m.ExpectedCalls, "Decrypt", args, originator) {
		return nil, errors.New("unexpected call to Decrypt")
	}
	call := m.Called(args, originator)
	return call.Get(0).(*wallet.DecryptResult), call.Error(1)
}

// CreateHmac returns a mocked HMAC result
func (m *MockableWallet) CreateHmac(ctx context.Context, args wallet.CreateHmacArgs, originator string) (*wallet.CreateHmacResult, error) {
	if !isExpectedMockCall(m.ExpectedCalls, "CreateHmac", args, originator) {
		return nil, errors.New("unexpected call to CreateHmac")
	}
	call := m.Called(args, originator)
	return call.Get(0).(*wallet.CreateHmacResult), call.Error(1)
}

// VerifyHmac returns a mocked HMAC verification result
func (m *MockableWallet) VerifyHmac(ctx context.Context, args wallet.VerifyHmacArgs, originator string) (*wallet.VerifyHmacResult, error) {
	if !isExpectedMockCall(m.ExpectedCalls, "VerifyHmac", args, originator) {
		return nil, errors.New("unexpected call to VerifyHmac")
	}
	call := m.Called(args, originator)
	return call.Get(0).(*wallet.VerifyHmacResult), call.Error(1)
}

// CreateSignature returns a mocked signature result
func (m *MockableWallet) CreateSignature(ctx context.Context, args wallet.CreateSignatureArgs, originator string) (*wallet.CreateSignatureResult, error) {
	if !isExpectedMockCall(m.ExpectedCalls, "CreateSignature", args, originator) {
		return nil, errors.New("unexpected call to CreateSignature")
	}
	call := m.Called(args, originator)
	return call.Get(0).(*wallet.CreateSignatureResult), call.Error(1)
}

// VerifySignature returns a mocked signature verification result
func (m *MockableWallet) VerifySignature(ctx context.Context, args wallet.VerifySignatureArgs, originator string) (*wallet.VerifySignatureResult, error) {
	if !isExpectedMockCall(m.ExpectedCalls, "VerifySignature", args) {
		return nil, errors.New("unexpected call to VerifySignature")
	}
	call := m.Called(args)
	return call.Get(0).(*wallet.VerifySignatureResult), call.Error(1)
}

// MockableWallet methods - Certificate Operations

// AcquireCertificate returns a mocked certificate
func (m *MockableWallet) AcquireCertificate(ctx context.Context, args wallet.AcquireCertificateArgs, originator string) (*wallet.Certificate, error) {
	if !isExpectedMockCall(m.ExpectedCalls, "AcquireCertificate", args, originator) {
		return nil, errors.New("unexpected call to AcquireCertificate")
	}
	call := m.Called(args, originator)
	return call.Get(0).(*wallet.Certificate), call.Error(1)
}

// ListCertificates returns mocked certificate list
func (m *MockableWallet) ListCertificates(ctx context.Context, args wallet.ListCertificatesArgs, originator string) (*wallet.ListCertificatesResult, error) {
	if !isExpectedMockCall(m.ExpectedCalls, "ListCertificates", args, originator) {
		return nil, errors.New("unexpected call to ListCertificates")
	}
	call := m.Called(args, originator)
	return call.Get(0).(*wallet.ListCertificatesResult), call.Error(1)
}

// ProveCertificate returns a mocked certificate proof
func (m *MockableWallet) ProveCertificate(ctx context.Context, args wallet.ProveCertificateArgs, originator string) (*wallet.ProveCertificateResult, error) {
	if !isExpectedMockCall(m.ExpectedCalls, "ProveCertificate", args, originator) {
		return nil, errors.New("unexpected call to ProveCertificate")
	}
	call := m.Called(args, originator)
	return call.Get(0).(*wallet.ProveCertificateResult), call.Error(1)
}

// RelinquishCertificate returns a mocked relinquish result
func (m *MockableWallet) RelinquishCertificate(ctx context.Context, args wallet.RelinquishCertificateArgs, originator string) (*wallet.RelinquishCertificateResult, error) {
	if !isExpectedMockCall(m.ExpectedCalls, "RelinquishCertificate", args, originator) {
		return nil, errors.New("unexpected call to RelinquishCertificate")
	}
	call := m.Called(args, originator)
	return call.Get(0).(*wallet.RelinquishCertificateResult), call.Error(1)
}

// CreateAction returns the not implemented error
func (m *MockableWallet) CreateAction(ctx context.Context, args wallet.CreateActionArgs, originator string) (*wallet.CreateActionResult, error) {
	return nil, errors.New("CreateAction not implemented in ExampleWallet")
}

// SignAction returns the not implemented error
func (m *MockableWallet) SignAction(ctx context.Context, args wallet.SignActionArgs, originator string) (*wallet.SignActionResult, error) {
	return nil, errors.New("SignAction not implemented in ExampleWallet")
}

// AbortAction returns the not implemented error
func (m *MockableWallet) AbortAction(ctx context.Context, args wallet.AbortActionArgs, originator string) (*wallet.AbortActionResult, error) {
	return nil, errors.New("AbortAction not implemented in ExampleWallet")
}

// ListActions returns the not implemented error
func (m *MockableWallet) ListActions(ctx context.Context, args wallet.ListActionsArgs, originator string) (*wallet.ListActionsResult, error) {
	return nil, errors.New("ListActions not implemented in ExampleWallet")
}

// InternalizeAction returns the not implemented error
func (m *MockableWallet) InternalizeAction(ctx context.Context, args wallet.InternalizeActionArgs, originator string) (*wallet.InternalizeActionResult, error) {
	return nil, errors.New("InternalizeAction not implemented in ExampleWallet")
}

// ListOutputs returns the not implemented error
func (m *MockableWallet) ListOutputs(ctx context.Context, args wallet.ListOutputsArgs, originator string) (*wallet.ListOutputsResult, error) {
	return nil, errors.New("ListOutputs not implemented in ExampleWallet")
}

// RelinquishOutput returns the not implemented error
func (m *MockableWallet) RelinquishOutput(ctx context.Context, args wallet.RelinquishOutputArgs, originator string) (*wallet.RelinquishOutputResult, error) {
	return nil, errors.New("RelinquishOutput not implemented in ExampleWallet")
}

// RevealCounterpartyKeyLinkage returns the not implemented error
func (m *MockableWallet) RevealCounterpartyKeyLinkage(ctx context.Context, args wallet.RevealCounterpartyKeyLinkageArgs, originator string) (*wallet.RevealCounterpartyKeyLinkageResult, error) {
	return nil, errors.New("RevealCounterpartyKeyLinkage not implemented in ExampleWallet")
}

// RevealSpecificKeyLinkage the not implemented error
func (m *MockableWallet) RevealSpecificKeyLinkage(ctx context.Context, args wallet.RevealSpecificKeyLinkageArgs, originator string) (*wallet.RevealSpecificKeyLinkageResult, error) {
	return nil, errors.New("RevealSpecificKeyLinkage not implemented in ExampleWallet")
}

// DiscoverByIdentityKey the not implemented error
func (m *MockableWallet) DiscoverByIdentityKey(ctx context.Context, args wallet.DiscoverByIdentityKeyArgs, originator string) (*wallet.DiscoverCertificatesResult, error) {
	return nil, errors.New("DiscoverByIdentityKey not implemented in ExampleWallet")
}

// DiscoverByAttributes the not implemented error
func (m *MockableWallet) DiscoverByAttributes(ctx context.Context, args wallet.DiscoverByAttributesArgs, originator string) (*wallet.DiscoverCertificatesResult, error) {
	return nil, errors.New("DiscoverByAttributes not implemented in ExampleWallet")
}

// IsAuthenticated returns the not implemented error
func (m *MockableWallet) IsAuthenticated(ctx context.Context, args any, originator string) (*wallet.AuthenticatedResult, error) {
	return nil, errors.New("IsAuthenticated not implemented in ExampleWallet")
}

// WaitForAuthentication returns the not implemented error
func (m *MockableWallet) WaitForAuthentication(ctx context.Context, args any, originator string) (*wallet.AuthenticatedResult, error) {
	return nil, errors.New("WaitForAuthentication not implemented in ExampleWallet")
}

// GetHeight returns the not implemented error
func (m *MockableWallet) GetHeight(ctx context.Context, args any, originator string) (*wallet.GetHeightResult, error) {
	return nil, errors.New("GetHeight not implemented in ExampleWallet")
}

// GetHeaderForHeight returns the not implemented error
func (m *MockableWallet) GetHeaderForHeight(ctx context.Context, args wallet.GetHeaderArgs, originator string) (*wallet.GetHeaderResult, error) {
	return nil, errors.New("GetHeaderForHeight not implemented in ExampleWallet")
}

// GetNetwork returns the not implemented error
func (m *MockableWallet) GetNetwork(ctx context.Context, args any, originator string) (*wallet.GetNetworkResult, error) {
	return nil, errors.New("GetNetwork not implemented in ExampleWallet")
}

// GetVersion returns the not implemented error
func (m *MockableWallet) GetVersion(ctx context.Context, args any, originator string) (*wallet.GetVersionResult, error) {
	return nil, errors.New("GetVersion not implemented in ExampleWallet")
}

// MockableWallet helper methods for test expectations

// OnGetPublicKeyOnce sets up a one-time expectation for GetPublicKey
func (m *MockableWallet) OnGetPublicKeyOnce(result *wallet.GetPublicKeyResult, err error) *mock.Call {
	return m.On("GetPublicKey", mock.Anything, mock.Anything).Return(result, err).Once()
}

// OnEncryptOnce sets up a one-time expectation for Encrypt
func (m *MockableWallet) OnEncryptOnce(result *wallet.EncryptResult, err error) *mock.Call {
	return m.On("Encrypt", mock.Anything, mock.Anything).Return(result, err).Once()
}

// OnDecryptOnce sets up a one-time expectation for Decrypt
func (m *MockableWallet) OnDecryptOnce(result *wallet.DecryptResult, err error) *mock.Call {
	return m.On("Decrypt", mock.Anything, mock.Anything).Return(result, err).Once()
}

// OnCreateHmacOnce sets up a one-time expectation for CreateHmac
func (m *MockableWallet) OnCreateHmacOnce(result *wallet.CreateHmacResult, err error) *mock.Call {
	return m.On("CreateHmac", mock.Anything, mock.Anything).Return(result, err).Once()
}

// OnVerifyHmacOnce sets up a one-time expectation for VerifyHmac
func (m *MockableWallet) OnVerifyHmacOnce(result *wallet.VerifyHmacResult, err error) *mock.Call {
	return m.On("VerifyHmac", mock.Anything, mock.Anything).Return(result, err).Once()
}

// OnCreateSignatureOnce sets up a one-time expectation for CreateSignature
func (m *MockableWallet) OnCreateSignatureOnce(result *wallet.CreateSignatureResult, err error) *mock.Call {
	return m.On("CreateSignature", mock.Anything, mock.Anything).Return(result, err).Once()
}

// OnVerifySignatureOnce sets up a one-time expectation for VerifySignature
func (m *MockableWallet) OnVerifySignatureOnce(result *wallet.VerifySignatureResult, err error) *mock.Call {
	return m.On("VerifySignature", mock.Anything).Return(result, err).Once()
}

// OnAcquireCertificateOnce sets up a one-time expectation for AcquireCertificate
func (m *MockableWallet) OnAcquireCertificateOnce(result *wallet.Certificate, err error) *mock.Call {
	return m.On("AcquireCertificate", mock.Anything, mock.Anything).Return(result, err).Once()
}

// OnListCertificatesOnce sets up a one-time expectation for ListCertificates
func (m *MockableWallet) OnListCertificatesOnce(result *wallet.ListCertificatesResult, err error) *mock.Call {
	return m.On("ListCertificates", mock.Anything, mock.Anything).Return(result, err).Once()
}

// OnProveCertificateOnce sets up a one-time expectation for ProveCertificate
func (m *MockableWallet) OnProveCertificateOnce(result *wallet.ProveCertificateResult, err error) *mock.Call {
	return m.On("ProveCertificate", mock.Anything, mock.Anything).Return(result, err).Once()
}

// OnRelinquishCertificateOnce sets up a one-time expectation for RelinquishCertificate
func (m *MockableWallet) OnRelinquishCertificateOnce(result *wallet.RelinquishCertificateResult, err error) *mock.Call {
	return m.On("RelinquishCertificate", mock.Anything, mock.Anything).Return(result, err).Once()
}

// OnCreateNonceOnce sets up a one-time expectation for CreateNonce
func (m *MockableWallet) OnCreateNonceOnce(nonce string, err error) *mock.Call {
	return m.On("CreateNonce", mock.Anything).Return(nonce, err).Once()
}

// OnVerifyNonceOnce sets up a one-time expectation for VerifyNonce
func (m *MockableWallet) OnVerifyNonceOnce(isValid bool, err error) *mock.Call {
	return m.On("VerifyNonce", mock.Anything, mock.Anything).Return(isValid, err).Once()
}

// GetPublicKey retrieves the public key based on the provided arguments
func (w *Wallet) GetPublicKey(ctx context.Context, args wallet.GetPublicKeyArgs, _ string) (*wallet.GetPublicKeyResult, error) {
	if args.IdentityKey {
		counterparty := wallet.Counterparty{
			Type: wallet.CounterpartyTypeSelf,
		}

		protocol := wallet.Protocol{
			SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty,
			Protocol:      "identity",
		}

		pubKey, err := w.keyDeriver.DerivePublicKey(
			protocol,
			"identity",
			counterparty,
			true,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to derive identity key: %w", err)
		}

		return &wallet.GetPublicKeyResult{
			PublicKey: pubKey,
		}, nil
	}

	if args.ProtocolID.Protocol == "" || args.KeyID == "" {
		return nil, errors.New("protocolID and keyID are required if identityKey is false")
	}

	counterparty := args.Counterparty
	if counterparty.Type == wallet.CounterpartyUninitialized {
		counterparty = wallet.Counterparty{
			Type: wallet.CounterpartyTypeSelf,
		}
	}

	pubKey, err := w.keyDeriver.DerivePublicKey(
		args.ProtocolID,
		args.KeyID,
		counterparty,
		args.ForSelf,
	)
	if err != nil {
		return nil, err
	}

	return &wallet.GetPublicKeyResult{
		PublicKey: pubKey,
	}, nil
}

// Encrypt provides a minimal implementation of encryption
func (w *Wallet) Encrypt(ctx context.Context, args wallet.EncryptArgs, _ string) (*wallet.EncryptResult, error) {
	return &wallet.EncryptResult{
		Ciphertext: args.Plaintext,
	}, nil
}

// Decrypt provides a minimal implementation of decryption
func (w *Wallet) Decrypt(ctx context.Context, args wallet.DecryptArgs, _ string) (*wallet.DecryptResult, error) {
	return &wallet.DecryptResult{
		Plaintext: args.Ciphertext,
	}, nil
}

// CreateHmac provides a minimal implementation for HMAC creation
func (w *Wallet) CreateHmac(ctx context.Context, args wallet.CreateHmacArgs, _ string) (*wallet.CreateHmacResult, error) {
	sum := sha256.Sum256(args.Data)
	return &wallet.CreateHmacResult{
		Hmac: sum[:],
	}, nil
}

// VerifyHmac provides a minimal HMAC verification
func (w *Wallet) VerifyHmac(ctx context.Context, args wallet.VerifyHmacArgs, _ string) (*wallet.VerifyHmacResult, error) {
	return &wallet.VerifyHmacResult{
		Valid: true,
	}, nil
}

// CreateSignature creates a digital signature
func (w *Wallet) CreateSignature(ctx context.Context, args wallet.CreateSignatureArgs, _ string) (*wallet.CreateSignatureResult, error) {
	var hash []byte
	if len(args.HashToDirectlySign) > 0 {
		hash = args.HashToDirectlySign
	} else {
		sum := sha256.Sum256(args.Data)
		hash = sum[:]
	}

	counterparty := args.Counterparty
	if counterparty.Type == wallet.CounterpartyUninitialized {
		counterparty = wallet.Counterparty{
			Type: wallet.CounterpartyTypeAnyone,
		}
	}

	privKey, err := w.keyDeriver.DerivePrivateKey(
		args.ProtocolID,
		args.KeyID,
		counterparty,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to derive private key: %w", err)
	}

	signature, err := privKey.Sign(hash)
	if err != nil {
		return nil, fmt.Errorf("failed to create signature: %w", err)
	}

	return &wallet.CreateSignatureResult{
		Signature: *signature,
	}, nil
}

// VerifySignature checks the validity of a cryptographic signature
func (w *Wallet) VerifySignature(ctx context.Context, args wallet.VerifySignatureArgs, _ string) (*wallet.VerifySignatureResult, error) {
	var hash []byte
	if len(args.HashToDirectlyVerify) > 0 {
		hash = args.HashToDirectlyVerify
	} else {
		sum := sha256.Sum256(args.Data)
		hash = sum[:]
	}

	counterparty := args.Counterparty
	if counterparty.Type == wallet.CounterpartyUninitialized {
		counterparty = wallet.Counterparty{
			Type: wallet.CounterpartyTypeSelf,
		}
	}

	pubKey, err := w.keyDeriver.DerivePublicKey(
		args.ProtocolID,
		args.KeyID,
		counterparty,
		args.ForSelf,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to derive public key: %w", err)
	}

	valid := args.Signature.Verify(hash, pubKey)
	return &wallet.VerifySignatureResult{
		Valid: valid,
	}, nil
}

// AcquireCertificate is a simplified mock implementation
func (w *Wallet) AcquireCertificate(ctx context.Context, args wallet.AcquireCertificateArgs, originator string) (*wallet.Certificate, error) {
	if args.Type == "" || args.Certifier == "" {
		return nil, errors.New("missing required fields")
	}

	return &wallet.Certificate{
		Type:         args.Type,
		SerialNumber: args.SerialNumber,
		Fields:       args.Fields,
		Signature:    args.Signature,
	}, nil
}

// ListCertificates returns a minimal certificate list
func (w *Wallet) ListCertificates(ctx context.Context, args wallet.ListCertificatesArgs, _ string) (*wallet.ListCertificatesResult, error) {
	return &wallet.ListCertificatesResult{
		TotalCertificates: 0,
		Certificates:      []wallet.CertificateResult{},
	}, nil
}

// ProveCertificate provides a minimal certificate proof
func (w *Wallet) ProveCertificate(ctx context.Context, args wallet.ProveCertificateArgs, _ string) (*wallet.ProveCertificateResult, error) {
	keyring := make(map[string]string)
	for _, field := range args.FieldsToReveal {
		keyring[field] = "mock-key-" + field
	}

	return &wallet.ProveCertificateResult{
		KeyringForVerifier: keyring,
	}, nil
}

// RelinquishCertificate provides a minimal certificate relinquishment
func (w *Wallet) RelinquishCertificate(ctx context.Context, args wallet.RelinquishCertificateArgs, _ string) (*wallet.RelinquishCertificateResult, error) {
	return &wallet.RelinquishCertificateResult{
		Relinquished: true,
	}, nil
}

// CreateNonce generates a deterministic nonce
func (w *Wallet) CreateNonce(ctx context.Context) (string, error) {
	if ctx.Err() != nil {
		return "", fmt.Errorf("ctx err: %w", ctx.Err())
	}

	newNonce := MockNonce

	if len(w.nonces) != 0 {
		newNonce = w.nonces[0]
		w.nonces = w.nonces[1:]

		if len(w.nonces) == 0 {
			w.nonces = append([]string(nil), DefaultNonces...)
		}
	}

	w.validNonces[newNonce] = true
	return newNonce, nil
}

// VerifyNonce checks if the nonce exists
func (w *Wallet) VerifyNonce(ctx context.Context, nonce string) (bool, error) {
	if ctx.Err() != nil {
		return false, fmt.Errorf("ctx err: %w", ctx.Err())
	}

	_, exists := w.validNonces[nonce]
	return exists, nil
}

// CreateAction is placeholder for creating an action
func (w *Wallet) CreateAction(ctx context.Context, args wallet.CreateActionArgs, originator string) (*wallet.CreateActionResult, error) {
	return nil, errors.New("CreateAction not implemented in ExampleWallet")
}

// SignAction is placeholder for signing an action
func (w *Wallet) SignAction(ctx context.Context, args wallet.SignActionArgs, originator string) (*wallet.SignActionResult, error) {
	return nil, errors.New("SignAction not implemented in ExampleWallet")
}

// AbortAction is placeholder for aborting an action
func (w *Wallet) AbortAction(ctx context.Context, args wallet.AbortActionArgs, originator string) (*wallet.AbortActionResult, error) {
	return nil, errors.New("AbortAction not implemented in ExampleWallet")
}

// ListActions is placeholder for listing actions
func (w *Wallet) ListActions(ctx context.Context, args wallet.ListActionsArgs, originator string) (*wallet.ListActionsResult, error) {
	return nil, errors.New("ListActions not implemented in ExampleWallet")
}

// InternalizeAction is placeholder for internalizing an action
func (w *Wallet) InternalizeAction(ctx context.Context, args wallet.InternalizeActionArgs, originator string) (*wallet.InternalizeActionResult, error) {
	return nil, errors.New("InternalizeAction not implemented in ExampleWallet")
}

// ListOutputs is placeholder for listing outputs
func (w *Wallet) ListOutputs(ctx context.Context, args wallet.ListOutputsArgs, originator string) (*wallet.ListOutputsResult, error) {
	return nil, errors.New("ListOutputs not implemented in ExampleWallet")
}

// RelinquishOutput is placeholder for relinquishing an output
func (w *Wallet) RelinquishOutput(ctx context.Context, args wallet.RelinquishOutputArgs, originator string) (*wallet.RelinquishOutputResult, error) {
	return nil, errors.New("RelinquishOutput not implemented in ExampleWallet")
}

// RevealCounterpartyKeyLinkage is placeholder for revealing counterparty key linkage
func (w *Wallet) RevealCounterpartyKeyLinkage(ctx context.Context, args wallet.RevealCounterpartyKeyLinkageArgs, originator string) (*wallet.RevealCounterpartyKeyLinkageResult, error) {
	return nil, errors.New("RevealCounterpartyKeyLinkage not implemented in ExampleWallet")
}

// RevealSpecificKeyLinkage is placeholder for revealing specific key linkage
func (w *Wallet) RevealSpecificKeyLinkage(ctx context.Context, args wallet.RevealSpecificKeyLinkageArgs, originator string) (*wallet.RevealSpecificKeyLinkageResult, error) {
	return nil, errors.New("RevealSpecificKeyLinkage not implemented in ExampleWallet")
}

// DiscoverByIdentityKey is placeholder for discovering by identity key
func (w *Wallet) DiscoverByIdentityKey(ctx context.Context, args wallet.DiscoverByIdentityKeyArgs, originator string) (*wallet.DiscoverCertificatesResult, error) {
	return nil, errors.New("DiscoverByIdentityKey not implemented in ExampleWallet")
}

// DiscoverByAttributes is placeholder for discovering by attributes
func (w *Wallet) DiscoverByAttributes(ctx context.Context, args wallet.DiscoverByAttributesArgs, originator string) (*wallet.DiscoverCertificatesResult, error) {
	return nil, errors.New("DiscoverByAttributes not implemented in ExampleWallet")
}

// IsAuthenticated is placeholder for checking authentication
func (w *Wallet) IsAuthenticated(ctx context.Context, args any, originator string) (*wallet.AuthenticatedResult, error) {
	return nil, errors.New("IsAuthenticated not implemented in ExampleWallet")
}

// WaitForAuthentication is placeholder for waiting for authentication
func (w *Wallet) WaitForAuthentication(ctx context.Context, args any, originator string) (*wallet.AuthenticatedResult, error) {
	return nil, errors.New("WaitForAuthentication not implemented in ExampleWallet")
}

// GetHeight is placeholder for getting height
func (w *Wallet) GetHeight(ctx context.Context, args any, originator string) (*wallet.GetHeightResult, error) {
	return nil, errors.New("GetHeight not implemented in ExampleWallet")
}

// GetHeaderForHeight is placeholder for getting header for height
func (w *Wallet) GetHeaderForHeight(ctx context.Context, args wallet.GetHeaderArgs, originator string) (*wallet.GetHeaderResult, error) {
	return nil, errors.New("GetHeaderForHeight not implemented in ExampleWallet")
}

// GetNetwork is placeholder for getting network
func (w *Wallet) GetNetwork(ctx context.Context, args any, originator string) (*wallet.GetNetworkResult, error) {
	return nil, errors.New("GetNetwork not implemented in ExampleWallet")
}

// GetVersion is placeholder for getting version
func (w *Wallet) GetVersion(ctx context.Context, args any, originator string) (*wallet.GetVersionResult, error) {
	return nil, errors.New("GetVersion not implemented in ExampleWallet")
}
