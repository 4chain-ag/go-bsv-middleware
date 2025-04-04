package ginadapter

import (
	"net/http"

	"github.com/4chain-ag/go-bsv-middleware/pkg/middleware/auth"
	"github.com/gin-gonic/gin"
)

// AuthMiddleware creates a Gin handler for BRC-103/104 authentication
func AuthMiddleware(opts auth.Config) gin.HandlerFunc {
	standardMiddleware := auth.New(opts)

	return func(c *gin.Context) {
		handler := standardMiddleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c.Request = r
			c.Next()
		}))

		handler.ServeHTTP(c.Writer, c.Request)

		if c.Writer.Written() {
			c.Abort()
		}
	}
}
