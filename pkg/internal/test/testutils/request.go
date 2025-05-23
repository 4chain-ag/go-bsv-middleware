package testutils

import (
	"fmt"
	"io"
	"net/http"
	"strings"
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

// InternalServerError checks if the response status code is 500.
func InternalServerError(t *testing.T, res *http.Response) {
	require.NotNil(t, res)
	require.Equal(t, http.StatusInternalServerError, res.StatusCode)
}

// MissingHeaderError check if the response body contain the "missing X header" error.
func MissingHeaderError(t *testing.T, res *http.Response, header string) {
	errString := readBody(t, res)
	require.Contains(t, fmt.Sprintf("missing %s header\n", header), errString)
}

// ReadBodyForTest reads and returns the response body for testing purposes
func ReadBodyForTest(t *testing.T, res *http.Response) string {
	return strings.ToLower(readBody(t, res))
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
