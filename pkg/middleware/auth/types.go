package auth

import (
	"log/slog"

	"github.com/bsv-blockchain/go-sdk/auth"
	"github.com/bsv-blockchain/go-sdk/auth/utils"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// Config configures the auth middleware
type Config struct {
	Wallet                 wallet.Interface
	SessionManager         auth.SessionManager
	AllowUnauthenticated   bool
	Logger                 *slog.Logger
	CertificatesToRequest  *utils.RequestedCertificateSet
	OnCertificatesReceived auth.OnCertificateReceivedCallback
}
