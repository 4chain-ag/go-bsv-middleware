package logging

import (
	"fmt"
	"log/slog"
	"os"
)

const (
	ServiceKey = "service"
	ErrorKey   = "error"
)

// Child returns a new logger with the given service name added to the logger attrs.
func Child(logger *slog.Logger, serviceName string) *slog.Logger {
	return DefaultIfNil(logger).With(
		slog.String(ServiceKey, serviceName),
	)
}

func Error(err error) slog.Attr {
	return slog.String(ErrorKey, err.Error())
}

// Fatalf logs the error and exits the program.
func Fatalf(logger *slog.Logger, err error, format string, args ...any) {
	logger.Error("Fatal error: "+fmt.Sprintf(format, args...), Error(err))
	os.Exit(1)
}

// DefaultIfNil returns the default logger if the given logger is nil.
func DefaultIfNil(logger *slog.Logger) *slog.Logger {
	if logger == nil {
		return slog.Default()
	}
	return logger
}
