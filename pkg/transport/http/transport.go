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

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/constants"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/interfaces"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/internal/logging"
	"github.com/bsv-blockchain/go-sdk/auth"
	"github.com/bsv-blockchain/go-sdk/auth/utils"
	primitives "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

type contextKey string

// IdentityKey stores identity in context.
const IdentityKey contextKey = "identity_key"

// RequestKey stores request in context.
const RequestKey contextKey = "http_request"

// ResponseKey stores response writer in context.
const ResponseKey contextKey = "http_response"

// NextKey stores the next handler in context.
const NextKey contextKey = "http_next_handler"

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
	n, err := r.ResponseWriter.Write(b)
	if err != nil {
		return n, fmt.Errorf("failed to write response: %w", err)
	}
	r.written = true
	return n, nil
}

func (r *responseRecorder) hasBeenWritten() bool {
	return r.written
}

// WrapResponseWriter wraps and tracks write status.
func WrapResponseWriter(w http.ResponseWriter) *responseRecorder {
	return &responseRecorder{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
	}
}

// HasBeenWritten checks if a response was written.
func HasBeenWritten(w http.ResponseWriter) bool {
	if rw, ok := w.(*responseRecorder); ok {
		return rw.hasBeenWritten()
	}
	return false
}

// TransportConfig config for Transport.
type TransportConfig struct {
	Wallet                 interfaces.Wallet
	SessionManager         auth.SessionManager
	Logger                 *slog.Logger
	CertificatesToRequest  *utils.RequestedCertificateSet
	OnCertificatesReceived auth.OnCertificateReceivedCallback
}

// Transport is an HTTP-based auth transport.
type Transport struct {
	wallet                 interfaces.Wallet
	sessionManager         auth.SessionManager
	logger                 *slog.Logger
	messageCallback        func(context.Context, *auth.AuthMessage) error
	certificatesToRequest  *utils.RequestedCertificateSet
	onCertificatesReceived auth.OnCertificateReceivedCallback
}

// New creates a new Transport.
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

// OnData sets callback for received messages.
func (t *Transport) OnData(callback func(context.Context, *auth.AuthMessage) error) error {
	if callback == nil {
		return errors.New("callback cannot be nil")
	}

	if t.messageCallback != nil {
		t.logger.Warn("OnData callback is overriding an already registered message callback")
	}

	t.messageCallback = callback
	t.logger.Debug("Registered OnData callback")
	return nil
}

// GetRegisteredOnData returns the current callback.
func (t *Transport) GetRegisteredOnData() (func(context.Context, *auth.AuthMessage) error, error) {
	if t.messageCallback == nil {
		return nil, errors.New("no callback registered")
	}

	return t.messageCallback, nil
}

// Send writes an auth message via HTTP.
func (t *Transport) Send(ctx context.Context, message *auth.AuthMessage) error {
	if message.IdentityKey == nil {
		return errors.New("message identity key cannot be nil")
	}

	respVal := ctx.Value(ResponseKey)
	if respVal == nil {
		return errors.New("response writer not found in context")
	}

	resp, ok := respVal.(http.ResponseWriter)
	if !ok {
		return errors.New("invalid response writer type in context")
	}

	switch message.MessageType {
	case auth.MessageTypeInitialResponse, auth.MessageTypeCertificateResponse:
		resp.Header().Set(constants.HeaderVersion, message.Version)
		resp.Header().Set(constants.HeaderMessageType, string(message.MessageType))
		resp.Header().Set(constants.HeaderIdentityKey, message.IdentityKey.ToDERHex())

		if message.Nonce != "" {
			resp.Header().Set(constants.HeaderNonce, message.Nonce)
		}

		if message.YourNonce != "" {
			resp.Header().Set(constants.HeaderYourNonce, message.YourNonce)
		}

		if message.Signature != nil {
			resp.Header().Set(constants.HeaderSignature, hex.EncodeToString(message.Signature))
		}

		resp.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(resp).Encode(message); err != nil {
			return fmt.Errorf("failed to encode message to JSON: %w", err)
		}

		return nil

	case auth.MessageTypeGeneral:
		req, ok := ctx.Value(RequestKey).(*http.Request)
		if !ok {
			return errors.New("invalid request type in context")
		}

		requestID := ""
		if req != nil {
			requestID = req.Header.Get(constants.HeaderRequestID)
		}

		resp.Header().Set(constants.HeaderVersion, message.Version)
		resp.Header().Set(constants.HeaderMessageType, string(message.MessageType))
		resp.Header().Set(constants.HeaderIdentityKey, message.IdentityKey.ToDERHex())

		if message.Nonce != "" {
			resp.Header().Set(constants.HeaderNonce, message.Nonce)
		}

		if message.YourNonce != "" {
			resp.Header().Set(constants.HeaderYourNonce, message.YourNonce)
		}

		if message.Signature != nil {
			resp.Header().Set(constants.HeaderSignature, hex.EncodeToString(message.Signature))
		}

		if requestID != "" {
			resp.Header().Set(constants.HeaderRequestID, requestID)
		}

		nextVal := ctx.Value(NextKey)
		if nextVal != nil {
			if next, ok := nextVal.(func()); ok {
				next()
			} else {
				t.logger.Warn("Next handler has invalid type in context")
			}
		}

		return nil

	case auth.MessageTypeCertificateRequest, auth.MessageTypeInitialRequest:
		return fmt.Errorf("message type %s is not supported in Send method", message.MessageType)

	default:
		return fmt.Errorf("unsupported message type: %s", message.MessageType)
	}
}

// ParseAuthMessageFromRequest parses auth message from HTTP request.
func ParseAuthMessageFromRequest(req *http.Request) (*auth.AuthMessage, error) {
	if req.URL.Path == constants.WellKnownAuthPath && req.Method == http.MethodPost {
		var message auth.AuthMessage
		if err := json.NewDecoder(req.Body).Decode(&message); err != nil {
			return nil, fmt.Errorf("invalid request body: %w", err)
		}

		if message.IdentityKey == nil {
			identityKeyHeader := req.Header.Get(constants.HeaderIdentityKey)
			if identityKeyHeader != "" {
				pubKey, err := primitives.PublicKeyFromString(identityKeyHeader)
				if err != nil {
					return nil, fmt.Errorf("invalid identity key format in header: %w", err)
				}
				message.IdentityKey = pubKey
			} else {
				return nil, errors.New("missing identity key in both request body and header")
			}
		}

		return &message, nil
	}

	version := req.Header.Get(constants.HeaderVersion)
	if version == "" {
		return nil, nil
	}

	identityKey := req.Header.Get(constants.HeaderIdentityKey)
	if identityKey == "" {
		return nil, errors.New("missing identity key header")
	}

	nonce := req.Header.Get(constants.HeaderNonce)
	yourNonce := req.Header.Get(constants.HeaderYourNonce)
	signature := req.Header.Get(constants.HeaderSignature)
	requestID := req.Header.Get(constants.HeaderRequestID)

	pubKey, err := primitives.PublicKeyFromString(identityKey)
	if err != nil {
		return nil, fmt.Errorf("invalid identity key format: %w", err)
	}

	payload, err := buildRequestPayload(req, requestID)
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

func buildRequestPayload(req *http.Request, requestID string) ([]byte, error) {
	writer := new(bytes.Buffer)

	requestIDBytes, err := base64.StdEncoding.DecodeString(requestID)
	if err != nil {
		return nil, fmt.Errorf("invalid request ID format: %w", err)
	}
	_, err = writer.Write(requestIDBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to write request ID: %w", err)
	}

	if err = writeString(writer, req.Method); err != nil {
		return nil, fmt.Errorf("failed to write request method: %w", err)
	}

	if err = writeOptionalString(writer, req.URL.Path); err != nil {
		return nil, fmt.Errorf("failed to write request path: %w", err)
	}

	if err = writeOptionalString(writer, req.URL.RawQuery); err != nil {
		return nil, fmt.Errorf("failed to write request query: %w", err)
	}

	var includedHeaders [][]string
	for k, v := range req.Header {
		if isIncludedHeader(k) {
			includedHeaders = append(includedHeaders, []string{strings.ToLower(k), v[0]})
		}
	}

	sort.Slice(includedHeaders, func(i, j int) bool {
		return includedHeaders[i][0] < includedHeaders[j][0]
	})

	if err := writeVarInt(writer, len(includedHeaders)); err != nil {
		return nil, fmt.Errorf("failed to write headers count: %w", err)
	}

	for _, header := range includedHeaders {
		if err := writeString(writer, header[0]); err != nil {
			return nil, fmt.Errorf("failed to write header key: %w", err)
		}

		if err := writeString(writer, header[1]); err != nil {
			return nil, fmt.Errorf("failed to write header value: %w", err)
		}
	}

	body, err := bodyContent(req)
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %w", err)
	}

	if len(body) > 0 {
		req.Body = io.NopCloser(bytes.NewBuffer(body))

		if err = writeBytes(writer, body); err != nil {
			return nil, fmt.Errorf("failed to write request body: %w", err)
		}
	} else {
		if err := writeVarInt(writer, -1); err != nil {
			return nil, fmt.Errorf("failed to write nil body marker: %w", err)
		}
	}
	return writer.Bytes(), nil
}

func isIncludedHeader(headerKey string) bool {
	k := strings.ToLower(headerKey)
	return (strings.HasPrefix(k, "x-bsv-") || k == "content-type" || k == "authorization") &&
		!strings.HasPrefix(k, constants.AuthHeaderPrefix)
}

func writeString(writer *bytes.Buffer, str string) error {
	if err := writeVarInt(writer, len(str)); err != nil {
		return fmt.Errorf("failed to write string length: %w", err)
	}
	if _, err := writer.WriteString(str); err != nil {
		return fmt.Errorf("failed to write string: %w", err)
	}
	return nil
}

func writeOptionalString(writer *bytes.Buffer, str string) error {
	if str == "" {
		if err := writeVarInt(writer, -1); err != nil {
			return fmt.Errorf("failed to write empty string placeholder: %w", err)
		}
		return nil
	}

	if err := writeString(writer, str); err != nil {
		return fmt.Errorf("failed to write optional string: %w", err)
	}
	return nil
}

func writeVarInt(w *bytes.Buffer, n int) error {
	err := binary.Write(w, binary.LittleEndian, int64(n))
	if err != nil {
		return fmt.Errorf("failed to write variable integer: %w", err)
	}
	return nil
}

func bodyContent(req *http.Request) ([]byte, error) {
	if req.Body == nil {
		return nil, nil
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %w", err)
	}

	return body, nil
}

func writeBytes(writer *bytes.Buffer, data []byte) error {
	if err := writeVarInt(writer, len(data)); err != nil {
		return fmt.Errorf("failed to write bytes length: %w", err)
	}
	if _, err := writer.Write(data); err != nil {
		return fmt.Errorf("failed to write bytes: %w", err)
	}
	return nil
}
