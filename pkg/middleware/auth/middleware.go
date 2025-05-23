package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/constants"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/interfaces"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/logging"
	httptransport "github.com/bsv-blockchain/go-bsv-middleware/pkg/transport/http"
	"github.com/bsv-blockchain/go-sdk/auth"
	sdkUtils "github.com/bsv-blockchain/go-sdk/auth/utils"
)

// Middleware is an HTTP middleware that handles authentication messages.
type Middleware struct {
	wallet               interfaces.Wallet
	peer                 *auth.Peer
	sessionManager       auth.SessionManager
	transport            auth.Transport
	allowUnauthenticated bool
	logger               *slog.Logger
}

// New creates a new instance of the auth middleware.
func New(cfg Config) (*Middleware, error) {
	if cfg.Wallet == nil {
		return nil, errors.New("wallet is required")
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	middlewareLogger := logging.Child(logger, "auth-middleware")

	sessionManager := cfg.SessionManager
	if sessionManager == nil {
		sessionManager = auth.NewSessionManager()
	}

	if cfg.OnCertificatesReceived == nil && cfg.CertificatesToRequest != nil {
		return nil, errors.New("OnCertificatesReceived callback is required when certificates are requested")
	}

	if cfg.OnCertificatesReceived != nil && cfg.CertificatesToRequest == nil {
		return nil, errors.New("OnCertificatesReceived callback is set but no certificates are requested")
	}

	transportCfg := httptransport.TransportConfig{
		Wallet:                 cfg.Wallet,
		SessionManager:         sessionManager,
		Logger:                 logger,
		CertificatesToRequest:  cfg.CertificatesToRequest,
		OnCertificatesReceived: cfg.OnCertificatesReceived,
	}

	t := httptransport.New(transportCfg)

	peerCfg := &auth.PeerOptions{
		Wallet:                cfg.Wallet,
		Transport:             t,
		SessionManager:        sessionManager,
		CertificatesToRequest: cfg.CertificatesToRequest,
	}
	peer := auth.NewPeer(peerCfg)
	peer.ListenForCertificatesReceived(cfg.OnCertificatesReceived)

	return &Middleware{
		peer:                 peer,
		wallet:               cfg.Wallet,
		sessionManager:       sessionManager,
		transport:            t,
		allowUnauthenticated: cfg.AllowUnauthenticated,
		logger:               middlewareLogger,
	}, nil
}

// Handler returns an HTTP handler that processes authentication messages.
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wrappedWriter := httptransport.WrapResponseWriter(w)

		ctx := context.WithValue(r.Context(), httptransport.RequestKey, r)
		ctx = context.WithValue(ctx, httptransport.ResponseKey, wrappedWriter)
		ctx = context.WithValue(ctx, httptransport.NextKey, func() {
			next.ServeHTTP(wrappedWriter, r)
		})

		m.logger.Debug("Processing request",
			slog.String("path", r.URL.Path),
			slog.String("method", r.Method))

		authMsg, err := httptransport.ParseAuthMessageFromRequest(r)
		if err != nil {
			m.logger.Error("Failed to parse auth message", slog.String("error", err.Error()))
			http.Error(wrappedWriter, err.Error(), http.StatusBadRequest)
			return
		}

		if authMsg == nil {
			if m.allowUnauthenticated {
				r = r.WithContext(context.WithValue(r.Context(), httptransport.IdentityKey, constants.UnknownParty))
				next.ServeHTTP(wrappedWriter, r)
				return
			} else {
				http.Error(wrappedWriter, "Authentication required", http.StatusUnauthorized)
				return
			}
		}

		// At this point, authMsg.IdentityKey should always be set by ParseAuthMessageFromRequest
		// If it's not set, that's an internal error
		if authMsg.IdentityKey == nil {
			m.logger.Error("Internal error: ParseAuthMessageFromRequest returned message with nil IdentityKey")
			http.Error(wrappedWriter, "Internal authentication error", http.StatusInternalServerError)
			return
		}

		callback, err := m.transport.GetRegisteredOnData()
		if err != nil {
			m.logger.Error("No message handler registered", slog.String("error", err.Error()))
			http.Error(wrappedWriter, "Server configuration error", http.StatusInternalServerError)
			return
		}

		if err := callback(ctx, authMsg); err != nil {
			m.logger.Error("Failed to process auth message", slog.String("error", err.Error()))

			statusCode := http.StatusInternalServerError
			errMsg := "Internal server error"

			switch {
			case errors.Is(err, auth.ErrNotAuthenticated):
				statusCode = http.StatusUnauthorized
				errMsg = "Authentication failed"
			case errors.Is(err, auth.ErrMissingCertificate):
				statusCode = http.StatusBadRequest
				var certTypes sdkUtils.RequestedCertificateTypeIDAndFieldList
				if m.peer != nil && m.peer.CertificatesToRequest != nil {
					certTypes = m.peer.CertificatesToRequest.CertificateTypes
				}
				errMsg = prepareMissingCertificateTypesErrorMsg(certTypes)
			case errors.Is(err, auth.ErrInvalidNonce):
				statusCode = http.StatusBadRequest
				errMsg = "Invalid nonce"
			case errors.Is(err, auth.ErrInvalidMessage):
				statusCode = http.StatusBadRequest
				errMsg = "Invalid message format"
			case errors.Is(err, auth.ErrSessionNotFound):
				statusCode = http.StatusUnauthorized
				errMsg = "Session not found"
			}

			http.Error(wrappedWriter, errMsg, statusCode)
			return
		}

		if !httptransport.HasBeenWritten(wrappedWriter) {
			r = r.WithContext(context.WithValue(r.Context(), httptransport.IdentityKey, authMsg.IdentityKey.ToDERHex()))
			next.ServeHTTP(wrappedWriter, r)
		}
	})
}

// prepareMissingCertificateTypesErrorMsg prepares a user-friendly error message for missing certificate types.
func prepareMissingCertificateTypesErrorMsg(missingCertTypes sdkUtils.RequestedCertificateTypeIDAndFieldList) string {
	if len(missingCertTypes) == 0 {
		return ""
	}

	var typesWithFields []string
	var typesWithoutFields []string

	for certType, fields := range missingCertTypes {
		typeName := getReadableCertTypeName(certType)

		if len(fields) > 0 {
			fieldStr := fmt.Sprintf("%s (fields: %s)", typeName, strings.Join(fields, ", "))
			typesWithFields = append(typesWithFields, fieldStr)
		} else {
			typesWithoutFields = append(typesWithoutFields, typeName)
		}
	}

	withFields := ""
	if len(typesWithFields) > 0 {
		withFields = " with fields"
	}
	allMissing := append(typesWithFields, typesWithoutFields...)
	return fmt.Sprintf("Missing required certificates%s: %s", withFields, strings.Join(allMissing, ", "))
}

// getReadableCertTypeName returns a shortened version of the certificate type ID for better readability.
func getReadableCertTypeName(certTypeID string) string {
	if len(certTypeID) > 16 && !strings.Contains(certTypeID, " ") {
		return certTypeID[:8] + "..." + certTypeID[len(certTypeID)-8:]
	}
	return certTypeID
}
