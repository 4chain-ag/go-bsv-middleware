package httptransport

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/interfaces"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/logging"
	"github.com/bsv-blockchain/go-sdk/auth"
	"github.com/bsv-blockchain/go-sdk/auth/certificates"
	"github.com/bsv-blockchain/go-sdk/auth/utils"
	primitives "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

type contextKey string

const (
	// IdentityKey is the key used to store the identity key in the context
	IdentityKey contextKey = "identity_key"
	// RequestKey is the key used to store the request in the context
	RequestKey contextKey = "http_request"
	// ResponseKey is the key used to store the response writer in the context
	ResponseKey contextKey = "http_response"
	// NextKey is the key used to store the next handler in the context
	NextKey contextKey = "http_next_handler"

	// HTTP headers - as specified in BRC-104
	authHeaderPrefix  = "x-bsv-auth-"
	versionHeader     = authHeaderPrefix + "version"
	messageTypeHeader = authHeaderPrefix + "message-type"
	identityKeyHeader = authHeaderPrefix + "identity-key"
	nonceHeader       = authHeaderPrefix + "nonce"
	yourNonceHeader   = authHeaderPrefix + "your-nonce"
	signatureHeader   = authHeaderPrefix + "signature"
	requestIDHeader   = authHeaderPrefix + "request-id"
)

type responseRecorder struct {
	http.ResponseWriter
	written    bool
	statusCode int
}

func (r *responseRecorder) WriteHeader(code int) {
	r.statusCode = code
	r.ResponseWriter.WriteHeader(code)
	r.written = true
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	r.written = true
	return r.ResponseWriter.Write(b)
}

func (r *responseRecorder) hasBeenWritten() bool {
	return r.written
}

// WrapResponseWriter wraps the http.ResponseWriter to capture the status code and written state
func WrapResponseWriter(w http.ResponseWriter) *responseRecorder {
	return &responseRecorder{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
	}
}

// TransportConfig holds configuration for the HTTP transport
type TransportConfig struct {
	Wallet                 interfaces.Wallet
	SessionManager         auth.SessionManager
	Logger                 *slog.Logger
	CertificatesToRequest  *utils.RequestedCertificateSet
	OnCertificatesReceived func(string, []*certificates.VerifiableCertificate, *http.Request, http.ResponseWriter, func())
}

// Transport implements the auth.Transport interface for HTTP transport
type Transport struct {
	wallet                 interfaces.Wallet
	sessionManager         auth.SessionManager
	logger                 *slog.Logger
	messageCallback        func(context.Context, *auth.AuthMessage) error
	certificatesToRequest  *utils.RequestedCertificateSet
	onCertificatesReceived func(string, []*certificates.VerifiableCertificate, *http.Request, http.ResponseWriter, func())
}

// New creates a new HTTP transport instance with the provided configuration
func New(cfg TransportConfig) auth.Transport {
	var logger *slog.Logger
	if cfg.Logger != nil {
		logger = logging.Child(cfg.Logger, "http-transport")
	} else {
		logger = slog.New(slog.DiscardHandler)
	}

	return &Transport{
		wallet:                 cfg.Wallet,
		sessionManager:         cfg.SessionManager,
		logger:                 logger,
		certificatesToRequest:  cfg.CertificatesToRequest,
		onCertificatesReceived: cfg.OnCertificatesReceived,
	}
}

// OnData registers a callback for incoming auth messages
// Required by BRC-104 to handle message exchanges
func (t *Transport) OnData(callback func(context.Context, *auth.AuthMessage) error) error {
	if callback == nil {
		return errors.New("callback cannot be nil")
	}

	t.messageCallback = callback
	t.logger.Debug("Registered OnData callback")
	return nil
}

// GetRegisteredOnData retrieves the registered callback for incoming auth messages
func (t *Transport) GetRegisteredOnData() (func(context.Context, *auth.AuthMessage) error, error) {
	if t.messageCallback == nil {
		return nil, errors.New("no callback registered")
	}

	return t.messageCallback, nil
}

// Send handles sending auth messages through HTTP
// BRC-104 requires specific headers and formatting based on message type
func (t *Transport) Send(ctx context.Context, message *auth.AuthMessage) error {
	respVal := ctx.Value(ResponseKey)
	if respVal == nil {
		return errors.New("response writer not found in context")
	}

	resp, ok := respVal.(http.ResponseWriter)
	if !ok {
		return errors.New("invalid response writer type in context")
	}

	nextVal := ctx.Value(NextKey)
	var next func()
	if nextVal != nil {
		next, ok = nextVal.(func())
		if !ok {
			t.logger.Warn("Next handler has invalid type in context")
		}
	}

	switch message.MessageType {
	case auth.MessageTypeInitialResponse, auth.MessageTypeCertificateResponse:
		resp.Header().Set(versionHeader, message.Version)
		resp.Header().Set(messageTypeHeader, string(message.MessageType))
		resp.Header().Set(identityKeyHeader, message.IdentityKey.ToDERHex())

		if message.Nonce != "" {
			resp.Header().Set(nonceHeader, message.Nonce)
		}

		if message.YourNonce != "" {
			resp.Header().Set(yourNonceHeader, message.YourNonce)
		}

		if message.Signature != nil {
			resp.Header().Set(signatureHeader, hex.EncodeToString(message.Signature))
		}

		resp.Header().Set("Content-Type", "application/json")
		return json.NewEncoder(resp).Encode(message)

	case auth.MessageTypeGeneral:
		req, _ := ctx.Value(RequestKey).(*http.Request)
		requestID := ""
		if req != nil {
			requestID = req.Header.Get(requestIDHeader)
		}

		resp.Header().Set(versionHeader, message.Version)
		resp.Header().Set(identityKeyHeader, message.IdentityKey.ToDERHex())

		if message.Nonce != "" {
			resp.Header().Set(nonceHeader, message.Nonce)
		}

		if message.YourNonce != "" {
			resp.Header().Set(yourNonceHeader, message.YourNonce)
		}

		if message.Signature != nil {
			resp.Header().Set(signatureHeader, hex.EncodeToString(message.Signature))
		}

		if requestID != "" {
			resp.Header().Set(requestIDHeader, requestID)
		}

		if next != nil {
			next()
		}
		return nil

	default:
		return fmt.Errorf("unsupported message type: %s", message.MessageType)
	}
}

// ParseAuthMessageFromRequest parses the auth message from the HTTP request
func ParseAuthMessageFromRequest(req *http.Request) (*auth.AuthMessage, error) {
	if req.URL.Path == "/.well-known/auth" && req.Method == http.MethodPost {
		var message auth.AuthMessage
		if err := json.NewDecoder(req.Body).Decode(&message); err != nil {
			return nil, fmt.Errorf("invalid request body: %w", err)
		}
		return &message, nil

	} else {
		version := req.Header.Get(versionHeader)
		if version == "" {
			return nil, nil
		}

		identityKey := req.Header.Get(identityKeyHeader)
		if identityKey == "" {
			return nil, errors.New("missing identity key header")
		}

		nonce := req.Header.Get(nonceHeader)
		yourNonce := req.Header.Get(yourNonceHeader)
		signature := req.Header.Get(signatureHeader)
		requestID := req.Header.Get(requestIDHeader)

		pubKey, err := primitives.PublicKeyFromString(identityKey)
		if err != nil {
			return nil, fmt.Errorf("invalid identity key format: %w", err)
		}

		payload, err := BuildRequestPayload(req, requestID)
		if err != nil {
			return nil, fmt.Errorf("failed to build request payload: %w", err)
		}

		message := &auth.AuthMessage{
			Version:     version,
			MessageType: auth.MessageTypeGeneral,
			IdentityKey: pubKey,
			Nonce:       nonce,
			YourNonce:   yourNonce,
			Payload:     payload,
		}

		if signature != "" {
			sigBytes, err := hex.DecodeString(signature)
			if err != nil {
				return nil, fmt.Errorf("invalid signature format: %w", err)
			}
			message.Signature = sigBytes
		}

		return message, nil
	}
}

// BuildRequestPayload creates a payload byte array from the request
// Format required by BRC-104 for consistent signing
func BuildRequestPayload(req *http.Request, requestID string) ([]byte, error) {
	writer := new(bytes.Buffer)

	requestIDBytes, err := base64.StdEncoding.DecodeString(requestID)
	if err != nil {
		return nil, fmt.Errorf("invalid request ID format: %w", err)
	}
	writer.Write(requestIDBytes)

	write := func(n int, desc string) error {
		if err := writeVarInt(writer, n); err != nil {
			return fmt.Errorf("%s: %w", desc, err)
		}
		return nil
	}

	if err := write(len(req.Method), "method length"); err != nil {
		return nil, err
	}
	writer.WriteString(req.Method)

	path := req.URL.Path
	if path == "" {
		if err := write(-1, "empty path marker"); err != nil {
			return nil, err
		}
	} else {
		if err := write(len(path), "path length"); err != nil {
			return nil, err
		}
		writer.WriteString(path)
	}

	query := req.URL.RawQuery
	if query == "" {
		if err := write(-1, "empty query marker"); err != nil {
			return nil, err
		}
	} else {
		if err := write(len(query), "query length"); err != nil {
			return nil, err
		}
		writer.WriteString(query)
	}

	includedHeaders := [][]string{}
	for k, v := range req.Header {
		k = strings.ToLower(k)
		if (strings.HasPrefix(k, "x-bsv-") || k == "content-type" || k == "authorization") &&
			!strings.HasPrefix(k, "x-bsv-auth") {
			includedHeaders = append(includedHeaders, []string{k, v[0]})
		}
	}

	// BRC-104 requires headers to be sorted lexicographically
	sort.Slice(includedHeaders, func(i, j int) bool {
		return includedHeaders[i][0] < includedHeaders[j][0]
	})

	if err := write(len(includedHeaders), "headers count"); err != nil {
		return nil, err
	}

	for _, header := range includedHeaders {
		if err := write(len(header[0]), "header key length"); err != nil {
			return nil, err
		}
		writer.WriteString(header[0])

		if err := write(len(header[1]), "header value length"); err != nil {
			return nil, err
		}
		writer.WriteString(header[1])
	}

	if req.Body != nil {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}

		req.Body = io.NopCloser(bytes.NewBuffer(body))

		if len(body) > 0 {
			if err := write(len(body), "body length"); err != nil {
				return nil, err
			}
			writer.Write(body)
		} else {
			if err := write(-1, "empty body marker"); err != nil {
				return nil, err
			}
		}
	} else {
		if err := write(-1, "nil body marker"); err != nil {
			return nil, err
		}
	}

	return writer.Bytes(), nil
}

func writeVarInt(w *bytes.Buffer, n int) error {
	err := binary.Write(w, binary.LittleEndian, int64(n))
	if err != nil {
		return fmt.Errorf("failed to write variable integer: %w", err)
	}
	return nil
}

// HasBeenWritten checks if the response writer has been written to
func HasBeenWritten(w http.ResponseWriter) bool {
	if rw, ok := w.(*responseRecorder); ok {
		return rw.hasBeenWritten()
	}
	return false
}
