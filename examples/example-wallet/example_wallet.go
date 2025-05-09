package wallet

import (
	"context"
	"errors"
	"fmt"

	"crypto/hmac"
	"crypto/sha256"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	hash "github.com/bsv-blockchain/go-sdk/primitives/hash"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// ExampleWallet is a mock implementation of the wallet interface
type ExampleWallet struct {
	keyDeriver *KeyDeriver
}
type ExampleWalletArgsType string

const (
	ExampleWalletArgsTypePrivateKey ExampleWalletArgsType = "privateKey"
	ExampleWalletArgsTypeKeyDeriver ExampleWalletArgsType = "keyDeriver"
	ExampleWalletArgsTypeAnyone     ExampleWalletArgsType = "anyone"
)

type ExampleWalletArgs struct {
	Type       ExampleWalletArgsType
	PrivateKey *ec.PrivateKey
	KeyDeriver *wallet.KeyDeriver
}

// NewExampleWallet creates a new ExampleWallet from a private key or KeyDeriver
func NewExampleWallet(rootKeyOrKeyDeriver ExampleWalletArgs) (*ExampleWallet, error) {
	switch rootKeyOrKeyDeriver.Type {
	case ExampleWalletArgsTypeKeyDeriver:
		return &ExampleWallet{
			keyDeriver: NewKeyDeriver(rootKeyOrKeyDeriver.PrivateKey),
		}, nil
	case ExampleWalletArgsTypePrivateKey:
		return &ExampleWallet{
			keyDeriver: NewKeyDeriver(rootKeyOrKeyDeriver.PrivateKey),
		}, nil
	case ExampleWalletArgsTypeAnyone:
		// Create an "anyone" key deriver as default
		kd := NewKeyDeriver(nil)
		return &ExampleWallet{
			keyDeriver: kd,
		}, nil
	}
	return nil, errors.New("invalid rootKeyOrKeyDeriver")
}

func (p *ExampleWallet) GetPublicKey(ctx context.Context, args wallet.GetPublicKeyArgs, _originator string) (*wallet.GetPublicKeyResult, error) {
	if args.IdentityKey {
		if p.keyDeriver == nil {
			return nil, errors.New("keyDeriver is undefined")
		}
		return &wallet.GetPublicKeyResult{
			PublicKey: p.keyDeriver.rootKey.PubKey(),
		}, nil
	} else {
		if args.ProtocolID.Protocol == "" || args.KeyID == "" {
			return nil, errors.New("protocolID and keyID are required if identityKey is false")
		}

		if p.keyDeriver == nil {
			return nil, errors.New("keyDeriver is undefined")
		}

		// Handle default counterparty (self)
		counterparty := args.Counterparty
		if counterparty.Type == wallet.CounterpartyUninitialized {
			counterparty = wallet.Counterparty{
				Type: wallet.CounterpartyTypeSelf,
			}
		}

		pubKey, err := p.keyDeriver.DerivePublicKey(
			args.ProtocolID,
			args.KeyID,
			counterparty,
			args.ForSelf,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to derive public key: %v", err)
		}
		return &wallet.GetPublicKeyResult{
			PublicKey: pubKey,
		}, nil
	}
}

// Encrypt encrypts data using the provided protocol ID and key ID
func (p *ExampleWallet) Encrypt(
	ctx context.Context,
	args wallet.EncryptArgs,
	originator string,
) (*wallet.EncryptResult, error) {

	if args.Counterparty.Type == wallet.CounterpartyUninitialized {
		args.Counterparty = wallet.Counterparty{
			Type: wallet.CounterpartyTypeSelf,
		}
	}

	if p.keyDeriver == nil {
		return nil, errors.New("keyDeriver is undefined")
	}

	// Create protocol struct from the protocol ID array
	protocol := args.ProtocolID

	// Handle counterparty
	counterpartyObj := args.Counterparty

	// Derive a symmetric key for encryption
	key, err := p.keyDeriver.DeriveSymmetricKey(protocol, args.KeyID, counterpartyObj)
	if err != nil {
		return nil, fmt.Errorf("failed to derive symmetric key: %v", err)
	}

	encrypted, err := key.Encrypt(args.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt: %v", err)
	}

	return &wallet.EncryptResult{
		Ciphertext: encrypted,
	}, nil
}

// Decrypt decrypts data using the provided protocol ID and key ID
func (p *ExampleWallet) Decrypt(
	ctx context.Context,
	args wallet.DecryptArgs,
	originator string,
) (*wallet.DecryptResult, error) {

	if p.keyDeriver == nil {
		return nil, errors.New("keyDeriver is undefined")
	}

	// Handle uninitialized counterparty - default to self
	counterparty := args.Counterparty
	if counterparty.Type == wallet.CounterpartyUninitialized {
		counterparty = wallet.Counterparty{
			Type: wallet.CounterpartyTypeSelf,
		}
	}

	// Derive a symmetric key for decryption
	key, err := p.keyDeriver.DeriveSymmetricKey(args.ProtocolID, args.KeyID, counterparty)
	if err != nil {
		return nil, fmt.Errorf("failed to derive symmetric key: %v", err)
	}

	plaintext, err := key.Decrypt(args.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %v", err)
	}

	return &wallet.DecryptResult{
		Plaintext: plaintext,
	}, nil
}

// CreateSignature creates a signature for the provided data
func (p *ExampleWallet) CreateSignature(
	ctx context.Context,
	args wallet.CreateSignatureArgs,
	originator string,
) (*wallet.CreateSignatureResult, error) {
	if p.keyDeriver == nil {
		return nil, errors.New("keyDeriver is undefined")
	}

	if len(args.Data) == 0 && len(args.HashToDirectlySign) == 0 {
		return nil, fmt.Errorf("args.data or args.hashToDirectlySign must be valid")
	}

	// Get hash to sign
	var dataHash []byte
	if len(args.HashToDirectlySign) > 0 {
		dataHash = args.HashToDirectlySign
	} else {
		dataHash = hash.Sha256(args.Data)
	}

	// Handle counterparty
	counterpartyObj := args.Counterparty
	if counterpartyObj.Type == wallet.CounterpartyUninitialized {
		counterpartyObj = wallet.Counterparty{
			Type: wallet.CounterpartyTypeAnyone,
		}
	}

	// Derive private key for signing
	privKey, err := p.keyDeriver.DerivePrivateKey(
		args.ProtocolID,
		args.KeyID,
		counterpartyObj,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to derive private key: %v", err)
	}

	// Create signature
	signature, err := privKey.Sign(dataHash)
	if err != nil {
		return nil, fmt.Errorf("failed to create signature: %v", err)
	}

	return &wallet.CreateSignatureResult{
		Signature: *signature,
	}, nil
}

// VerifySignature verifies a signature for the provided data
func (p *ExampleWallet) VerifySignature(
	ctx context.Context,
	args wallet.VerifySignatureArgs,
	originator string,
) (*wallet.VerifySignatureResult, error) {
	if p.keyDeriver == nil {
		return nil, errors.New("keyDeriver is undefined")
	}

	if len(args.Data) == 0 && len(args.HashToDirectlyVerify) == 0 {
		return nil, fmt.Errorf("args.data or args.hashToDirectlyVerify must be valid")
	}

	// Get hash to verify
	var dataHash []byte
	if len(args.HashToDirectlyVerify) > 0 {
		dataHash = args.HashToDirectlyVerify
	} else {
		dataHash = hash.Sha256(args.Data)
	}

	// Handle counterparty
	counterparty := args.Counterparty
	if counterparty.Type == wallet.CounterpartyUninitialized {
		counterparty = wallet.Counterparty{
			Type: wallet.CounterpartyTypeSelf,
		}
	}

	// Derive public key for verification
	pubKey, err := p.keyDeriver.DerivePublicKey(
		args.ProtocolID,
		args.KeyID,
		counterparty,
		args.ForSelf,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to derive public key: %v", err)
	}

	// Verify signature
	valid := args.Signature.Verify(dataHash, pubKey)
	if !valid {
		return nil, fmt.Errorf("signature is not valid")
	}

	return &wallet.VerifySignatureResult{
		Valid: valid,
	}, nil
}

// CreateHmac generates an HMAC (Hash-based Message Authentication Code) for the provided data
// using a symmetric key derived from the protocol, key ID, and counterparty.
func (p *ExampleWallet) CreateHmac(
	ctx context.Context,
	args wallet.CreateHmacArgs,
	originator string,
) (*wallet.CreateHmacResult, error) {
	if p.keyDeriver == nil {
		return nil, errors.New("keyDeriver is undefined")
	}

	// Handle default counterparty (self for HMAC)
	counterpartyObj := args.Counterparty
	if counterpartyObj.Type == wallet.CounterpartyUninitialized {
		counterpartyObj = wallet.Counterparty{
			Type: wallet.CounterpartyTypeSelf,
		}
	}

	// Derive a symmetric key for HMAC
	key, err := p.keyDeriver.DeriveSymmetricKey(
		args.ProtocolID,
		args.KeyID,
		counterpartyObj,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to derive symmetric key: %v", err)
	}

	// Create HMAC using the derived key
	mac := hmac.New(sha256.New, key.ToBytes())
	mac.Write(args.Data)
	hmacValue := mac.Sum(nil)

	return &wallet.CreateHmacResult{Hmac: hmacValue}, nil
}

// VerifyHmac verifies that the provided HMAC matches the expected value for the given data.
// The verification uses the same protocol, key ID, and counterparty that were used to create the HMAC.
func (p *ExampleWallet) VerifyHmac(
	ctx context.Context,
	args wallet.VerifyHmacArgs,
	originator string,
) (*wallet.VerifyHmacResult, error) {
	if p.keyDeriver == nil {
		return nil, errors.New("keyDeriver is undefined")
	}

	// Handle default counterparty (self for HMAC)
	counterpartyObj := args.Counterparty
	if counterpartyObj.Type == wallet.CounterpartyUninitialized {
		counterpartyObj = wallet.Counterparty{
			Type: wallet.CounterpartyTypeSelf,
		}
	}

	// Derive a symmetric key for HMAC verification
	key, err := p.keyDeriver.DeriveSymmetricKey(
		args.ProtocolID,
		args.KeyID,
		counterpartyObj,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to derive symmetric key: %v", err)
	}

	// Create expected HMAC
	mac := hmac.New(sha256.New, key.ToBytes())
	mac.Write(args.Data)
	expectedHmac := mac.Sum(nil)

	// Verify HMAC
	if !hmac.Equal(expectedHmac, args.Hmac) {
		return &wallet.VerifyHmacResult{Valid: false}, nil
	}

	return &wallet.VerifyHmacResult{Valid: true}, nil
}

// ListCertificates lists certificates that match the specified criteria
func (p *ExampleWallet) ListCertificates(ctx context.Context, args wallet.ListCertificatesArgs, originator string) (*wallet.ListCertificatesResult, error) {
	if p.keyDeriver == nil {
		return nil, errors.New("keyDeriver is undefined")
	}

	if len(args.Types) == 0 && len(args.Certifiers) == 0 {
		return nil, errors.New("at least one certificate type or certifier must be specified")
	}

	certificate := wallet.Certificate{
		Type:         "mock-age-verification",
		SerialNumber: "mock-12345",
		Subject:      p.keyDeriver.rootKey.PubKey(),
		Certifier:    p.keyDeriver.rootKey.PubKey(),
		Fields: map[string]string{
			"age":     "21",
			"country": "Switzerland",
		},
		Signature: "mocksignature",
	}

	certificates := []wallet.CertificateResult{}
	certificates = append(certificates, wallet.CertificateResult{
		Certificate: certificate,
		Keyring: map[string]string{
			"age":     "mock-keyring-age",
			"country": "mock-keyring-country",
		},
		Verifier: "mockverifier",
	})

	return &wallet.ListCertificatesResult{
		TotalCertificates: uint32(len(certificates)),
		Certificates:      certificates,
	}, nil
}

// AcquireCertificate validates and stores a certificate
func (p *ExampleWallet) AcquireCertificate(ctx context.Context, args wallet.AcquireCertificateArgs, originator string) (*wallet.Certificate, error) {
	if p.keyDeriver == nil {
		return nil, errors.New("keyDeriver is undefined")
	}

	// Validate required parameters
	if args.Type == "" {
		return nil, errors.New("certificate type is required")
	}

	if args.Certifier == "" {
		return nil, errors.New("certificate certifier is required")
	}

	if args.AcquisitionProtocol == "" {
		return nil, errors.New("certificate AcquisitionProtocol is required")
	}

	if args.Fields == nil {
		return nil, errors.New("certificate Fields is required")
	}

	if args.SerialNumber == "" {
		return nil, errors.New("certificate serial number is required")
	}

	if args.RevocationOutpoint == "" {
		return nil, errors.New("certificate revocation outpoint is required")
	}

	if args.Signature == "" {
		return nil, errors.New("certificate Signature is required")
	}

	if args.CertifierUrl == "" {
		return nil, errors.New("certificate CertifierUrl is required")
	}

	if args.KeyringRevealer == "" {
		return nil, errors.New("certificate KeyringRevealer is required")
	}

	if args.KeyringForSubject == nil {
		return nil, errors.New("certificate KeyringForSubject is required")
	}

	certifierKey, err := ec.PublicKeyFromString(args.Certifier)
	if err != nil {
		return nil, fmt.Errorf("invalid certifier key: %w", err)
	}

	subjectKeyResult, err := p.GetPublicKey(ctx, wallet.GetPublicKeyArgs{
		IdentityKey: true,
	}, originator)

	if err != nil {
		return nil, fmt.Errorf("failed to get wallet identity key: %w", err)
	}

	certificate := &wallet.Certificate{
		Type:               args.Type,
		SerialNumber:       args.SerialNumber,
		Subject:            subjectKeyResult.PublicKey,
		Certifier:          certifierKey,
		RevocationOutpoint: args.RevocationOutpoint,
		Fields:             args.Fields,
		Signature:          "mock-signature-placeholder",
	}

	return certificate, nil
}

// ProveCertificate creates a verifiable certificate with selectively revealed fields
func (p *ExampleWallet) ProveCertificate(ctx context.Context, args wallet.ProveCertificateArgs, originator string) (*wallet.ProveCertificateResult, error) {
	if p.keyDeriver == nil {
		return nil, errors.New("keyDeriver is undefined")
	}

	// Validate required parameters
	if args.Certificate.Type == "" {
		return nil, errors.New("certificate type is required")
	}
	if args.Certificate.SerialNumber == "" {
		return nil, errors.New("certificate serial number is required")
	}
	if args.Certificate.Subject == nil {
		return nil, errors.New("certificate subject is required")
	}
	if args.Certificate.Certifier == nil {
		return nil, errors.New("certificate certifier is required")
	}
	if len(args.FieldsToReveal) == 0 {
		return nil, errors.New("at least one field to reveal must be specified")
	}
	if args.Verifier == "" {
		return nil, errors.New("verifier is required")
	}

	// Prepare a mock keyring for the verifier that allows access to selected fields
	keyringForVerifier := make(map[string]string)

	// For each field to reveal, create a mock encrypted key entry
	for _, fieldName := range args.FieldsToReveal {
		// Check if the field exists in the certificate
		if _, exists := args.Certificate.Fields[fieldName]; !exists {
			return nil, fmt.Errorf("field '%s' does not exist in the certificate", fieldName)
		}

		// In a real implementation, this would create an encrypted field key
		// For ProtoWallet, just create a mock entry
		keyringForVerifier[fieldName] = fmt.Sprintf("mock-encrypted-key-for-%s", fieldName)
	}

	return &wallet.ProveCertificateResult{
		KeyringForVerifier: keyringForVerifier,
	}, nil
}

// RelinquishCertificate invalidates a certificate held by the wallet
func (p *ExampleWallet) RelinquishCertificate(ctx context.Context, args wallet.RelinquishCertificateArgs, originator string) (*wallet.RelinquishCertificateResult, error) {
	if p.keyDeriver == nil {
		return nil, errors.New("keyDeriver is undefined")
	}

	// Validate required parameters
	if args.SerialNumber == "" {
		return nil, errors.New("certificate serial number is required")
	}
	if args.Certifier == "" {
		return nil, errors.New("certificate certifier is required")
	}
	if args.Type == "" {
		return nil, errors.New("certificate type is required")
	}

	// For a ProtoWallet implementation, we simply return success
	// In a real implementation, this would invalidate the certificate in storage

	return &wallet.RelinquishCertificateResult{
		Relinquished: true,
	}, nil
}

func (p *ExampleWallet) CreateAction(ctx context.Context, args wallet.CreateActionArgs, originator string) (*wallet.CreateActionResult, error) {
	return nil, errors.New("CreateAction not implemented in ExampleWallet")
}

func (p *ExampleWallet) SignAction(ctx context.Context, args wallet.SignActionArgs, originator string) (*wallet.SignActionResult, error) {
	return nil, errors.New("SignAction not implemented in ExampleWallet")
}

func (p *ExampleWallet) AbortAction(ctx context.Context, args wallet.AbortActionArgs, originator string) (*wallet.AbortActionResult, error) {
	return nil, errors.New("AbortAction not implemented in ExampleWallet")
}

func (p *ExampleWallet) ListActions(ctx context.Context, args wallet.ListActionsArgs, originator string) (*wallet.ListActionsResult, error) {
	return nil, errors.New("ListActions not implemented in ExampleWallet")
}

func (p *ExampleWallet) InternalizeAction(ctx context.Context, args wallet.InternalizeActionArgs, originator string) (*wallet.InternalizeActionResult, error) {
	return nil, errors.New("InternalizeAction not implemented in ExampleWallet")
}

func (p *ExampleWallet) ListOutputs(ctx context.Context, args wallet.ListOutputsArgs, originator string) (*wallet.ListOutputsResult, error) {
	return nil, errors.New("ListOutputs not implemented in ExampleWallet")
}

func (p *ExampleWallet) RelinquishOutput(ctx context.Context, args wallet.RelinquishOutputArgs, originator string) (*wallet.RelinquishOutputResult, error) {
	return nil, errors.New("RelinquishOutput not implemented in ExampleWallet")
}

func (p *ExampleWallet) RevealCounterpartyKeyLinkage(ctx context.Context, args wallet.RevealCounterpartyKeyLinkageArgs, originator string) (*wallet.RevealCounterpartyKeyLinkageResult, error) {
	return nil, errors.New("RevealCounterpartyKeyLinkage not implemented in ExampleWallet")
}

func (p *ExampleWallet) RevealSpecificKeyLinkage(ctx context.Context, args wallet.RevealSpecificKeyLinkageArgs, originator string) (*wallet.RevealSpecificKeyLinkageResult, error) {
	return nil, errors.New("RevealSpecificKeyLinkage not implemented in ExampleWallet")
}

func (p *ExampleWallet) DiscoverByIdentityKey(ctx context.Context, args wallet.DiscoverByIdentityKeyArgs, originator string) (*wallet.DiscoverCertificatesResult, error) {
	return nil, errors.New("DiscoverByIdentityKey not implemented in ExampleWallet")
}

func (p *ExampleWallet) DiscoverByAttributes(ctx context.Context, args wallet.DiscoverByAttributesArgs, originator string) (*wallet.DiscoverCertificatesResult, error) {
	return nil, errors.New("DiscoverByAttributes not implemented in ExampleWallet")
}

func (p *ExampleWallet) IsAuthenticated(ctx context.Context, args any, originator string) (*wallet.AuthenticatedResult, error) {
	return nil, errors.New("IsAuthenticated not implemented in ExampleWallet")
}

func (p *ExampleWallet) WaitForAuthentication(ctx context.Context, args any, originator string) (*wallet.AuthenticatedResult, error) {
	return nil, errors.New("WaitForAuthentication not implemented in ExampleWallet")
}

func (p *ExampleWallet) GetHeight(ctx context.Context, args any, originator string) (*wallet.GetHeightResult, error) {
	return nil, errors.New("GetHeight not implemented in ExampleWallet")
}

func (p *ExampleWallet) GetHeaderForHeight(ctx context.Context, args wallet.GetHeaderArgs, originator string) (*wallet.GetHeaderResult, error) {
	return nil, errors.New("GetHeaderForHeight not implemented in ExampleWallet")
}

func (p *ExampleWallet) GetNetwork(ctx context.Context, args any, originator string) (*wallet.GetNetworkResult, error) {
	return nil, errors.New("GetNetwork not implemented in ExampleWallet")
}

func (p *ExampleWallet) GetVersion(ctx context.Context, args any, originator string) (*wallet.GetVersionResult, error) {
	return nil, errors.New("GetVersion not implemented in ExampleWallet")
}
