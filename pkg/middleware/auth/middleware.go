package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/interfaces"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/logging"
	httptransport "github.com/bsv-blockchain/go-bsv-middleware/pkg/transport/http"
	"github.com/bsv-blockchain/go-sdk/auth"
	sdkUtils "github.com/bsv-blockchain/go-sdk/auth/utils"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// Middleware is a struct that holds the configuration for the BRC authentication middleware
type Middleware struct {
	wallet               interfaces.Wallet
	peer                 *auth.Peer
	sessionManager       auth.SessionManager
	transport            auth.Transport
	allowUnauthenticated bool
	logger               *slog.Logger
}

// New creates a new instance of the BRC authentication middleware
func New(cfg Config) (*Middleware, error) {
	if cfg.Wallet == nil {
		return nil, errors.New("wallet is required")
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
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

	return &Middleware{
		peer:                 peer,
		wallet:               cfg.Wallet,
		sessionManager:       sessionManager,
		transport:            t,
		allowUnauthenticated: cfg.AllowUnauthenticated,
		logger:               middlewareLogger,
	}, nil
}

// Handler returns a middleware handler function for BRC authentication
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
				r = r.WithContext(context.WithValue(r.Context(), httptransport.IdentityKey, "unknown"))
				next.ServeHTTP(wrappedWriter, r)
				return
			} else {
				// BRC-104 requires 401 for authentication failures
				http.Error(wrappedWriter, "Authentication required", http.StatusUnauthorized)
				return
			}
		}

		if authMsg.IdentityKey == nil && r.Header.Get("x-bsv-auth-identity-key") != "" {
			pubKey, err := ec.PublicKeyFromString(r.Header.Get("x-bsv-auth-identity-key"))
			if err != nil {
				m.logger.Error("Failed to parse identity key", slog.String("error", err.Error()))
				http.Error(wrappedWriter, "Invalid identity key format", http.StatusBadRequest)
				return
			}
			authMsg.IdentityKey = pubKey
		}

		callback, err := m.transport.GetRegisteredOnData()
		if err != nil {
			m.logger.Error("No message handler registered", slog.String("error", err.Error()))
			http.Error(wrappedWriter, "Server configuration error", http.StatusInternalServerError)
			return
		}

		err = callback(ctx, authMsg)
		if err != nil {
			m.logger.Error("Failed to process auth message", slog.String("error", err.Error()))

			statusCode := http.StatusInternalServerError
			errMsg := err.Error()

			switch {
			case errors.Is(err, auth.ErrNotAuthenticated):
				statusCode = http.StatusUnauthorized
				errMsg = "Authentication failed"
			case errors.Is(err, auth.ErrMissingCertificate):
				statusCode = http.StatusBadRequest
				errMsg = prepareMissingCertificateTypesErrorMsg(m.peer.CertificatesToRequest.CertificateTypes)
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
			if authMsg.IdentityKey != nil {
				r = r.WithContext(context.WithValue(r.Context(), httptransport.IdentityKey, authMsg.IdentityKey.ToDERHex()))
			}

			next.ServeHTTP(wrappedWriter, r)
		}
	})
}

// prepareMissingCertificateTypesError creates a formatted error message for missing certificate types
// It accepts a RequestedCertificateTypeIDAndFieldList (map of type -> fields) and formats it into a readable error
func prepareMissingCertificateTypesErrorMsg(missingCertTypes sdkUtils.RequestedCertificateTypeIDAndFieldList) string {
	if len(missingCertTypes) == 0 {
		return ""
	}

	var typesWithFields []string
	var typesWithoutFields []string

	// Iterate through the map of certificate types and their fields
	for certType, fields := range missingCertTypes {
		typeName := getReadableCertTypeName(certType)

		if len(fields) > 0 {
			fieldStr := fmt.Sprintf("%s (fields: %s)", typeName, strings.Join(fields, ", "))
			typesWithFields = append(typesWithFields, fieldStr)
		} else {
			typesWithoutFields = append(typesWithoutFields, typeName)
		}
	}

	// Use a more detailed message if we have field information
	if len(typesWithFields) > 0 {
		if len(typesWithoutFields) > 0 {
			// Combine types with fields and types without fields
			allMissing := append(typesWithFields, typesWithoutFields...)
			return fmt.Sprintf("Missing required certificates: %s", strings.Join(allMissing, "; "))
		}
		return fmt.Sprintf("Missing required certificates with fields: %s", strings.Join(typesWithFields, "; "))
	}

	// Simple message when no field information is available
	return fmt.Sprintf("Missing required certificates: %s", strings.Join(typesWithoutFields, ", "))
}

// getReadableCertTypeName returns a more readable version of certificate type ID
// Certificate type IDs are often base64 encoded and difficult to read
func getReadableCertTypeName(certTypeID string) string {
	// If the certificate type ID looks like a base64 string, use a shortened version
	if len(certTypeID) > 16 && !strings.Contains(certTypeID, " ") {
		return certTypeID[:8] + "..." + certTypeID[len(certTypeID)-8:]
	}
	return certTypeID
}
