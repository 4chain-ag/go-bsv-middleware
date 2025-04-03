package auth

import (
	"log/slog"
	"net/http"

	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/sessionmanager"
	"github.com/4chain-ag/go-bsv-middleware/pkg/temporary/wallet"
	"github.com/4chain-ag/go-bsv-middleware/pkg/transport"
)

// Options configures the auth middleware
type Options struct {
	Wallet                 wallet.WalletInterface
	SessionManager         sessionmanager.SessionManagerInterface
	AllowUnauthenticated   bool
	Logger                 *slog.Logger
	CertificatesToRequest  *transport.RequestedCertificateSet
	OnCertificatesReceived func(senderPublicKey string, certs []wallet.VerifiableCertificate, req http.Request, res http.ResponseWriter) error
}
