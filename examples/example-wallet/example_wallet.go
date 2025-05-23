package wallet

import (
	"context"
	"errors"
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

const (
	// ErrNotImplemented is returned when a method is not implemented
	ErrNotImplemented = "not implemented"
)

// ExtendedProtoWallet wraps ProtoWallet and implements the full wallet.Interface
type ExtendedProtoWallet struct {
	*wallet.ProtoWallet
}

// NewExtendedProtoWallet creates a new ExtendedProtoWallet from a private key
func NewExtendedProtoWallet(privateKey *ec.PrivateKey) (*ExtendedProtoWallet, error) {
	protoWallet, err := wallet.NewProtoWallet(wallet.ProtoWalletArgs{
		Type:       wallet.ProtoWalletArgsTypePrivateKey,
		PrivateKey: privateKey,
	})
	if err != nil {
		return nil, err
	}

	return &ExtendedProtoWallet{
		ProtoWallet: protoWallet,
	}, nil
}

// Transaction-related methods (not needed for auth demo, return appropriate errors/defaults)
func (w *ExtendedProtoWallet) CreateAction(ctx context.Context, args wallet.CreateActionArgs, originator string) (*wallet.CreateActionResult, error) {
	return nil, fmt.Errorf("CreateAction: %s", ErrNotImplemented)
}

func (w *ExtendedProtoWallet) SignAction(ctx context.Context, args wallet.SignActionArgs, originator string) (*wallet.SignActionResult, error) {
	return nil, fmt.Errorf("SignAction: %s", ErrNotImplemented)
}

func (w *ExtendedProtoWallet) AbortAction(ctx context.Context, args wallet.AbortActionArgs, originator string) (*wallet.AbortActionResult, error) {
	return &wallet.AbortActionResult{Aborted: false}, nil
}

func (w *ExtendedProtoWallet) ListActions(ctx context.Context, args wallet.ListActionsArgs, originator string) (*wallet.ListActionsResult, error) {
	return &wallet.ListActionsResult{
		TotalActions: 0,
		Actions:      []wallet.Action{},
	}, nil
}

func (w *ExtendedProtoWallet) InternalizeAction(ctx context.Context, args wallet.InternalizeActionArgs, originator string) (*wallet.InternalizeActionResult, error) {
	// For demo purposes, always accept
	return &wallet.InternalizeActionResult{Accepted: true}, nil
}

func (w *ExtendedProtoWallet) ListOutputs(ctx context.Context, args wallet.ListOutputsArgs, originator string) (*wallet.ListOutputsResult, error) {
	return &wallet.ListOutputsResult{
		TotalOutputs: 0,
		Outputs:      []wallet.Output{},
	}, nil
}

func (w *ExtendedProtoWallet) RelinquishOutput(ctx context.Context, args wallet.RelinquishOutputArgs, originator string) (*wallet.RelinquishOutputResult, error) {
	return &wallet.RelinquishOutputResult{Relinquished: false}, nil
}

// Key linkage methods (return errors for demo)
func (w *ExtendedProtoWallet) RevealCounterpartyKeyLinkage(ctx context.Context, args wallet.RevealCounterpartyKeyLinkageArgs, originator string) (*wallet.RevealCounterpartyKeyLinkageResult, error) {
	return nil, errors.New("RevealCounterpartyKeyLinkage not implemented - this is an auth demo wallet")
}

func (w *ExtendedProtoWallet) RevealSpecificKeyLinkage(ctx context.Context, args wallet.RevealSpecificKeyLinkageArgs, originator string) (*wallet.RevealSpecificKeyLinkageResult, error) {
	return nil, errors.New("RevealSpecificKeyLinkage not implemented - this is an auth demo wallet")
}

// Certificate methods - implement basic functionality for demo
func (w *ExtendedProtoWallet) AcquireCertificate(ctx context.Context, args wallet.AcquireCertificateArgs, originator string) (*wallet.Certificate, error) {
	if args.Type == "" || args.Certifier == "" {
		return nil, errors.New("missing required certificate fields")
	}

	// Get our identity key for the subject
	identityResult, err := w.GetPublicKey(ctx, wallet.GetPublicKeyArgs{IdentityKey: true}, originator)
	if err != nil {
		return nil, err
	}

	// Parse certifier key
	certifierKey, err := ec.PublicKeyFromString(args.Certifier)
	if err != nil {
		return nil, err
	}

	return &wallet.Certificate{
		Type:               args.Type,
		SerialNumber:       args.SerialNumber,
		Subject:            identityResult.PublicKey,
		Certifier:          certifierKey,
		RevocationOutpoint: args.RevocationOutpoint,
		Fields:             args.Fields,
		Signature:          args.Signature,
	}, nil
}

func (w *ExtendedProtoWallet) ListCertificates(ctx context.Context, args wallet.ListCertificatesArgs, originator string) (*wallet.ListCertificatesResult, error) {
	// For demo purposes, return empty list
	return &wallet.ListCertificatesResult{
		TotalCertificates: 0,
		Certificates:      []wallet.CertificateResult{},
	}, nil
}

func (w *ExtendedProtoWallet) ProveCertificate(ctx context.Context, args wallet.ProveCertificateArgs, originator string) (*wallet.ProveCertificateResult, error) {
	if args.Certificate.Type == "" {
		return nil, errors.New("certificate type is required")
	}

	// Create mock keyring for demo
	keyring := make(map[string]string)
	for _, field := range args.FieldsToReveal {
		keyring[field] = "demo-encrypted-key-" + field
	}

	return &wallet.ProveCertificateResult{
		KeyringForVerifier: keyring,
	}, nil
}

func (w *ExtendedProtoWallet) RelinquishCertificate(ctx context.Context, args wallet.RelinquishCertificateArgs, originator string) (*wallet.RelinquishCertificateResult, error) {
	return &wallet.RelinquishCertificateResult{Relinquished: true}, nil
}

// Discovery methods (return empty results for demo)
func (w *ExtendedProtoWallet) DiscoverByIdentityKey(ctx context.Context, args wallet.DiscoverByIdentityKeyArgs, originator string) (*wallet.DiscoverCertificatesResult, error) {
	return &wallet.DiscoverCertificatesResult{
		TotalCertificates: 0,
		Certificates:      []wallet.IdentityCertificate{},
	}, nil
}

func (w *ExtendedProtoWallet) DiscoverByAttributes(ctx context.Context, args wallet.DiscoverByAttributesArgs, originator string) (*wallet.DiscoverCertificatesResult, error) {
	return &wallet.DiscoverCertificatesResult{
		TotalCertificates: 0,
		Certificates:      []wallet.IdentityCertificate{},
	}, nil
}

// Status methods (return defaults for demo)
func (w *ExtendedProtoWallet) IsAuthenticated(ctx context.Context, args any, originator string) (*wallet.AuthenticatedResult, error) {
	return &wallet.AuthenticatedResult{Authenticated: true}, nil
}

func (w *ExtendedProtoWallet) WaitForAuthentication(ctx context.Context, args any, originator string) (*wallet.AuthenticatedResult, error) {
	return &wallet.AuthenticatedResult{Authenticated: true}, nil
}

func (w *ExtendedProtoWallet) GetHeight(ctx context.Context, args any, originator string) (*wallet.GetHeightResult, error) {
	return &wallet.GetHeightResult{Height: 800000}, nil // Mock height
}

func (w *ExtendedProtoWallet) GetHeaderForHeight(ctx context.Context, args wallet.GetHeaderArgs, originator string) (*wallet.GetHeaderResult, error) {
	return &wallet.GetHeaderResult{Header: "mock-header"}, nil
}

func (w *ExtendedProtoWallet) GetNetwork(ctx context.Context, args any, originator string) (*wallet.GetNetworkResult, error) {
	return &wallet.GetNetworkResult{Network: "mainnet"}, nil
}

func (w *ExtendedProtoWallet) GetVersion(ctx context.Context, args any, originator string) (*wallet.GetVersionResult, error) {
	return &wallet.GetVersionResult{Version: "1.0.0-demo"}, nil
}
