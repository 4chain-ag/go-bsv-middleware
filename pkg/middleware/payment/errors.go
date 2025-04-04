package payment

import "errors"

var (
	// ErrNoWallet is returned when no wallet instance is provided
	ErrNoWallet = errors.New("a valid wallet instance must be supplied to the payment middleware")

	// ErrAuthMiddlewareMissing is returned when auth middleware did not run before payment middleware
	ErrAuthMiddlewareMissing = errors.New("the payment middleware must be executed after the Auth middleware")
)
