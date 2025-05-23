package testutils

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// ResponseContainsError checks if the response body contains the specified error substring.
func ResponseContainsError(t *testing.T, res *http.Response, errorSubstring string) {
	body := readBody(t, res)
	require.Contains(t, body, errorSubstring)
}

// InvalidNonceFormatError checks if the response body contains an invalid nonce format error.
func InvalidNonceFormatError(t *testing.T, res *http.Response) {
	ResponseContainsError(t, res, "invalid nonce format")
}

// NonceAlreadyUsedError checks if the response body contains a nonce already used error.
func NonceAlreadyUsedError(t *testing.T, res *http.Response) {
	ResponseContainsError(t, res, "nonce already used")
}

// MissingRequiredFieldsError checks if the response body contains a missing required fields error.
func MissingRequiredFieldsError(t *testing.T, res *http.Response) {
	ResponseContainsError(t, res, "missing required fields in initial request")
}

// UnsupportedVersionError checks if the response body contains an unsupported version error.
func UnsupportedVersionError(t *testing.T, res *http.Response) {
	ResponseContainsError(t, res, "unsupported version")
}
