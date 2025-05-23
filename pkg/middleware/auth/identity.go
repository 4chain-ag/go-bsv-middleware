package auth

import (
	"context"

	httptransport "github.com/bsv-blockchain/go-bsv-middleware/pkg/transport/http"
)

// GetIdentityFromContext retrieves identity from the request context
func GetIdentityFromContext(ctx context.Context) (string, bool) {
	value := ctx.Value(httptransport.IdentityKey)
	if value == nil {
		return "", false
	}

	identityKey, ok := value.(string)
	return identityKey, ok
}
