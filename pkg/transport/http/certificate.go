package httptransport

import (
	"errors"
	"log/slog"

	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
	"github.com/4chain-ag/go-bsv-middleware/pkg/transport"
)

// Certificate verification errors
var (
	ErrInvalidCertificate    = errors.New("invalid certificate")
	ErrMissingKeyring        = errors.New("missing keyring")
	ErrUntrustedCertifier    = errors.New("certificate from untrusted certifier")
	ErrMissingRequiredFields = errors.New("certificate missing required fields")
	ErrWrongCertificateType  = errors.New("wrong certificate type")
)

// CertificateVerifier verifies certificates against requirements
type CertificateVerifier struct {
	logger *slog.Logger
	// Requirements for different paths or resources
	requirements               *transport.RequestedCertificateSet
	onCertificatesReceivedFunc *transport.OnCertificatesReceivedFunc
}

// NewCertificateVerifier creates a new certificate verifier
func NewCertificateVerifier(logger *slog.Logger, cert *transport.RequestedCertificateSet, onCertificatesReceivedFunc *transport.OnCertificatesReceivedFunc) *CertificateVerifier {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	if cert == nil {
		cert = &transport.RequestedCertificateSet{}
	}

	if onCertificatesReceivedFunc == nil {
		logger.Info("onCertificatesReceivedFunc to be implemented")
	}

	return &CertificateVerifier{
		logger:                     logger.With("component", "CertificateVerifier"),
		requirements:               cert,
		onCertificatesReceivedFunc: nil,
	}
}

// HasRequirements returns true if there are any certificate requirements
func (cv *CertificateVerifier) HasRequirements() bool {
	return cv.requirements != nil
}

// VerifyCertificate verifies a certificate against requirements
func (cv *CertificateVerifier) VerifyCertificate(cert *wallet.VerifiableCertificate) error {
	if cert == nil {
		return ErrInvalidCertificate
	}

	if cert.Keyring == nil {
		return ErrMissingKeyring
	}

	_, ok := cv.requirements.Types[cert.Type]
	if !ok {
		return ErrWrongCertificateType
	}

	return nil
}
