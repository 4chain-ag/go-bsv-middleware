package assert

import (
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// ResponseOK checks if the response status code is 200.
func ResponseOK(t *testing.T, res *http.Response) {
	require.NotNil(t, res)
	require.Equal(t, http.StatusOK, res.StatusCode)
}

// BadRequest checks if the response status code is 400.
func BadRequest(t *testing.T, res *http.Response) {
	require.NotNil(t, res)
	require.Equal(t, http.StatusBadRequest, res.StatusCode)
}

// NotAuthorized checks if the response status code is 401.
func NotAuthorized(t *testing.T, res *http.Response) {
	require.NotNil(t, res)
	require.Equal(t, http.StatusUnauthorized, res.StatusCode)
}

// MissingRequestIDError checks if the response body contains the "missing request ID" error.
func MissingRequestIDError(t *testing.T, res *http.Response) {
	errString := readBody(t, res)
	require.Equal(t, "missing request ID", errString)
}

// UnableToVerifySignatureError checks if the response body contains the "unable to verify signature" error.
func UnableToVerifySignatureError(t *testing.T, res *http.Response) {
	errString := readBody(t, res)
	require.Contains(t, errString, "unable to verify signature")
}

// SessionNotFoundError check if the response body contain the "session not found" error.
func SessionNotFoundError(t *testing.T, res *http.Response) {
	errString := readBody(t, res)
	require.Equal(t, "session not found", errString)
}

// SessionNotAuthenticatedError check if the response body contain the "session not authenticated" error.
func SessionNotAuthenticatedError(t *testing.T, res *http.Response) {
	errString := readBody(t, res)
	require.Equal(t, "session not authenticated", errString)
}

// MissingHeaderError check if the response body contain the "missing X header" error.
func MissingHeaderError(t *testing.T, res *http.Response, header string) {
	errString := readBody(t, res)
	require.Equal(t, fmt.Sprintf("missing %s header", header), errString)
}

// InvalidHeaderError check if the response body contain the "invalid X header" error.
func InvalidHeaderError(t *testing.T, res *http.Response, header string) {
	errString := readBody(t, res)
	require.Equal(t, fmt.Sprintf("invalid %s header", header), errString)
}

func readBody(t *testing.T, res *http.Response) string {
	defer func() {
		err := res.Body.Close()
		require.NoError(t, err)
	}()
	body, err := io.ReadAll(res.Body)

	require.NoError(t, err)
	return string(body)
}
