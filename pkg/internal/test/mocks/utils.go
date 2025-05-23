package mocks

import (
	"github.com/stretchr/testify/mock"
)

func isExpectedMockCall(calls []*mock.Call, method string, arguments ...any) bool {
	for _, call := range calls {
		if call.Method == method {
			_, diffCount := call.Arguments.Diff(arguments)
			if diffCount == 0 {
				if call.Repeatability > -1 {
					return true
				}
			}
		}
	}
	return false
}
