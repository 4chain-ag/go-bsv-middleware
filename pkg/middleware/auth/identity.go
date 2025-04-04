package auth

import (
	"context"

	"github.com/4chain-ag/go-bsv-middleware/pkg/transport"
)

// GetIdentityFromContext retrieves identity from the request context
func GetIdentityFromContext(ctx context.Context) (string, bool) {
	value := ctx.Value(transport.IdentityKey)
	if value == nil {
		return "", false
	}

	identityKey, ok := value.(string)
	return identityKey, ok
}
