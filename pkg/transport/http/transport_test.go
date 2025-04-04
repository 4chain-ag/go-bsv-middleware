package httptransport

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/4chain-ag/go-bsv-middleware/pkg/transport"
	"github.com/4chain-ag/go-bsv-middleware/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTransport_SetupHeaders(t *testing.T) {
	tests := []struct {
		name        string
		authMsg     *transport.AuthMessage
		requestID   string
		wantHeaders map[string]string
	}{
		{
			name: "Basic Headers",
			authMsg: &transport.AuthMessage{
				Version:     "0.1",
				MessageType: transport.InitialResponse,
				IdentityKey: "test-key",
			},
			requestID: "12345",
			wantHeaders: map[string]string{
				"X-Bsv-Auth-Version":      "0.1",
				"X-Bsv-Auth-Message-Type": "initialResponse",
				"X-Bsv-Auth-Identity-Key": "test-key",
			},
		},
		{
			name: "General Message with Request ID",
			authMsg: &transport.AuthMessage{
				Version:     "0.1",
				MessageType: transport.General,
				IdentityKey: "test-key",
			},
			requestID: "abcde",
			wantHeaders: map[string]string{
				"X-Bsv-Auth-Version":      "0.1",
				"X-Bsv-Auth-Message-Type": "general",
				"X-Bsv-Auth-Identity-Key": "test-key",
				"X-Bsv-Auth-Request-ID":   "abcde",
			},
		},
		{
			name: "Headers with Nonce and YourNonce",
			authMsg: &transport.AuthMessage{
				Version:     "0.1",
				MessageType: transport.General,
				IdentityKey: "test-key",
				Nonce:       stringPtr("nonce-value"),
				YourNonce:   stringPtr("your-nonce-value"),
			},
			requestID: "xyz123",
			wantHeaders: map[string]string{
				"X-Bsv-Auth-Version":      "0.1",
				"X-Bsv-Auth-Message-Type": "general",
				"X-Bsv-Auth-Identity-Key": "test-key",
				"X-Bsv-Auth-Request-ID":   "xyz123",
				"X-Bsv-Auth-Nonce":        "nonce-value",
				"X-Bsv-Auth-Your-Nonce":   "your-nonce-value",
			},
		},
		{
			name: "Headers with Signature",
			authMsg: &transport.AuthMessage{
				Version:     "0.1",
				MessageType: transport.General,
				IdentityKey: "test-key",
				Signature:   bytePtr([]byte{0x12, 0x34, 0x56}),
			},
			requestID: "test-req-id",
			wantHeaders: map[string]string{
				"X-Bsv-Auth-Version":      "0.1",
				"X-Bsv-Auth-Message-Type": "general",
				"X-Bsv-Auth-Identity-Key": "test-key",
				"X-Bsv-Auth-Request-ID":   "test-req-id",
				"X-Bsv-Auth-Signature":    hex.EncodeToString([]byte{0x12, 0x34, 0x56}),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			recorder := httptest.NewRecorder()

			// when
			setupHeaders(recorder, tt.authMsg, tt.requestID)

			// then
			for key, expectedValue := range tt.wantHeaders {
				actualValue := recorder.Header().Get(key)
				assert.Equal(t, expectedValue, actualValue, "Header %s mismatch", key)
			}
		})
	}
}

func TestBuildResponsePayload(t *testing.T) {
	tests := []struct {
		name           string
		requestID      string
		responseStatus int
		responseBody   []byte
		expectErr      bool
	}{
		{
			name:           "Valid request ID and response body",
			requestID:      base64.StdEncoding.EncodeToString([]byte("test-request-id")),
			responseStatus: 200,
			responseBody:   []byte("response-data"),
			expectErr:      false,
		},
		{
			name:           "Invalid Base64 request ID",
			requestID:      "invalid_base64_!@#",
			responseStatus: 200,
			responseBody:   []byte("data"),
			expectErr:      true,
		},
		{
			name:           "Empty response body",
			requestID:      base64.StdEncoding.EncodeToString([]byte("empty-body-test")),
			responseStatus: 404,
			responseBody:   []byte{},
			expectErr:      false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// when
			payload, err := buildResponsePayload(tc.requestID, tc.responseStatus, tc.responseBody)

			// then
			if tc.expectErr {
				require.Error(t, err)
				return
			}

			require.NotNil(t, payload)

			reader := bytes.NewReader(payload)

			expectedRequestIDBytes, err := base64.StdEncoding.DecodeString(tc.requestID)
			require.NoError(t, err)
			actualRequestID := make([]byte, len(expectedRequestIDBytes))
			_, err = reader.Read(actualRequestID)
			require.NoError(t, err)
			assert.Equal(t, expectedRequestIDBytes, actualRequestID, "Request ID mismatch")

			responseStatus, err := utils.ReadVarIntNum(reader)
			require.NoError(t, err)
			assert.Equal(t, int64(tc.responseStatus), responseStatus, "Response status mismatch")

			headerCount, err := utils.ReadVarIntNum(reader)
			require.NoError(t, err)

			assert.Equal(t, int64(-1), headerCount, "Expected headers count to be -1")

			bodyLength, err := utils.ReadVarIntNum(reader)
			require.NoError(t, err)

			if len(tc.responseBody) == 0 {
				assert.Equal(t, int64(-1), bodyLength, "Empty response body should be encoded as -1")
			} else {
				assert.Equal(t, int64(len(tc.responseBody)), bodyLength, "Response body length mismatch")

				actualBody := make([]byte, bodyLength)
				_, err := reader.Read(actualBody)
				require.NoError(t, err)
				assert.Equal(t, tc.responseBody, actualBody, "Response body mismatch")
			}
		})
	}
}

func TestTransport_SetupContent(t *testing.T) {
	// given
	exampleContent := &transport.AuthMessage{
		Version:     "0.1",
		MessageType: transport.General,
		IdentityKey: "test-key",
	}
	recorder := httptest.NewRecorder()
	expectedBody, err := json.Marshal(exampleContent)
	assert.NoError(t, err)

	// when
	setupContent(recorder, exampleContent)

	// then
	assert.Equal(t, "application/json", recorder.Header().Get("Content-Type"))
	assert.Equal(t, expectedBody, recorder.Body.Bytes())
	assert.NotEqual(t, http.StatusInternalServerError, recorder.Code)
}

func TestTransport_BuildAuthMessageFromRequest(t *testing.T) {
	// given
	requestID := base64.StdEncoding.EncodeToString([]byte("test-request-id"))
	version := "0.1"
	identityKey := "test-identity-key"
	nonce := "test-nonce"
	yourNonce := "your-test-nonce"
	signatureHex := hex.EncodeToString([]byte("test_signature"))

	req, err := http.NewRequest("POST", "http://example.com/path?param1=value1&param2=value", nil)
	require.NoError(t, err)
	req.Header.Set("X-Bsv-Auth-Nonce", nonce)
	req.Header.Set("X-Bsv-Auth-Your-Nonce", yourNonce)
	req.Header.Set("X-Bsv-Auth-Signature", signatureHex)
	req.Header.Set("X-Bsv-Auth-Request-Id", requestID)
	req.Header.Set("X-Bsv-Auth-Version", version)
	req.Header.Set("X-Bsv-Auth-Identity-Key", identityKey)

	// when
	authMsg, err := buildAuthMessageFromRequest(req)

	// then
	assert.NoError(t, err)
	assert.NotNil(t, authMsg)
	assert.Equal(t, transport.General, authMsg.MessageType)
	assert.Equal(t, version, authMsg.Version)
	assert.Equal(t, identityKey, authMsg.IdentityKey)
	assert.Equal(t, nonce, *authMsg.Nonce)
	assert.Equal(t, yourNonce, *authMsg.YourNonce)
	expectedSignature, err := hex.DecodeString(signatureHex)
	assert.NoError(t, err)
	assert.Equal(t, expectedSignature, *authMsg.Signature)
	assert.NotEmpty(t, authMsg.Payload)
}

func stringPtr(s string) *string {
	return &s
}

func bytePtr(b []byte) *[]byte {
	return &b
}
