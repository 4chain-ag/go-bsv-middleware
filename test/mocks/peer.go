package mocks

import (
	"errors"

	"github.com/bsv-blockchain/go-sdk/auth"
	"github.com/bsv-blockchain/go-sdk/auth/certificates"
	sdkUtils "github.com/bsv-blockchain/go-sdk/auth/utils"
	"github.com/stretchr/testify/mock"
)

// MockablePeer is a mock implementation of the Peer interface.
type MockablePeer struct {
	mock.Mock
}

// NewMockablePeer creates a new instance of MockablePeer
func NewMockablePeer() *MockablePeer {
	return &MockablePeer{}
}

// ToPeer mocks sending a message to a peer
func (m *MockablePeer) ToPeer(message []byte, identityKey string, maxWaitTime int) error {
	if !isExpectedMockCall(m.ExpectedCalls, "ToPeer", message, identityKey, maxWaitTime) {
		return errors.New("unexpected call to ToPeer")
	}
	args := m.Called(message, identityKey, maxWaitTime)
	return args.Error(0)
}

// RequestCertificates mocks requesting certificates from a peer
func (m *MockablePeer) RequestCertificates(certificatesToRequest sdkUtils.RequestedCertificateSet, identityKey string, maxWaitTime int) error {
	if !isExpectedMockCall(m.ExpectedCalls, "RequestCertificates", certificatesToRequest, identityKey, maxWaitTime) {
		return errors.New("unexpected call to RequestCertificates")
	}
	args := m.Called(certificatesToRequest, identityKey, maxWaitTime)
	return args.Error(0)
}

// GetAuthenticatedSession mocks retrieving an authenticated session
func (m *MockablePeer) GetAuthenticatedSession(identityKey string, maxWaitTime int) (*auth.PeerSession, error) {
	if !isExpectedMockCall(m.ExpectedCalls, "GetAuthenticatedSession", identityKey, maxWaitTime) {
		return nil, errors.New("unexpected call to GetAuthenticatedSession")
	}
	args := m.Called(identityKey, maxWaitTime)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auth.PeerSession), args.Error(1)
}

// SendCertificateResponse mocks sending certificates to a peer
func (m *MockablePeer) SendCertificateResponse(verifierIdentityKey string, certificates []certificates.VerifiableCertificate) error {
	if !isExpectedMockCall(m.ExpectedCalls, "SendCertificateResponse", verifierIdentityKey, certificates) {
		return errors.New("unexpected call to SendCertificateResponse")
	}
	args := m.Called(verifierIdentityKey, certificates)
	return args.Error(0)
}

// ListenForGeneralMessages mocks registering a callback for general messages
func (m *MockablePeer) ListenForGeneralMessages(callback func(senderPublicKey string, payload []byte)) int {
	if !isExpectedMockCall(m.ExpectedCalls, "ListenForGeneralMessages", mock.Anything) {
		return -1
	}
	args := m.Called(callback)
	return args.Int(0)
}

// StopListeningForGeneralMessages mocks removing a general message listener
func (m *MockablePeer) StopListeningForGeneralMessages(callbackID int) {
	if !isExpectedMockCall(m.ExpectedCalls, "StopListeningForGeneralMessages", callbackID) {
		return
	}
	m.Called(callbackID)
}

// ListenForCertificatesReceived mocks registering a callback for certificates
func (m *MockablePeer) ListenForCertificatesReceived(callback func(senderPublicKey string, certs []certificates.VerifiableCertificate)) int {
	if !isExpectedMockCall(m.ExpectedCalls, "ListenForCertificatesReceived", mock.Anything) {
		return -1
	}
	args := m.Called(callback)
	return args.Int(0)
}

// StopListeningForCertificatesReceived mocks removing a certificate received listener
func (m *MockablePeer) StopListeningForCertificatesReceived(callbackID int) {
	if !isExpectedMockCall(m.ExpectedCalls, "StopListeningForCertificatesReceived", callbackID) {
		return
	}
	m.Called(callbackID)
}

// ListenForCertificatesRequested mocks registering a callback for certificate requests
func (m *MockablePeer) ListenForCertificatesRequested(callback func(senderPublicKey string, requestedCertificates sdkUtils.RequestedCertificateSet)) int {
	if !isExpectedMockCall(m.ExpectedCalls, "ListenForCertificatesRequested", mock.Anything) {
		return -1
	}
	args := m.Called(callback)
	return args.Int(0)
}

// StopListeningForCertificatesRequested mocks removing a certificate request listener
func (m *MockablePeer) StopListeningForCertificatesRequested(callbackID int) {
	if !isExpectedMockCall(m.ExpectedCalls, "StopListeningForCertificatesRequested", callbackID) {
		return
	}
	m.Called(callbackID)
}

// OnToPeerOnce sets up a one-time expectation for ToPeer
func (m *MockablePeer) OnToPeerOnce(message []byte, identityKey string, maxWaitTime int, err error) *mock.Call {
	return m.On("ToPeer", message, identityKey, maxWaitTime).Return(err).Once()
}

// OnRequestCertificatesOnce sets up a one-time expectation for RequestCertificates
func (m *MockablePeer) OnRequestCertificatesOnce(certificatesToRequest sdkUtils.RequestedCertificateSet, identityKey string, maxWaitTime int, err error) *mock.Call {
	return m.On("RequestCertificates", certificatesToRequest, identityKey, maxWaitTime).Return(err).Once()
}

// OnGetAuthenticatedSessionOnce sets up a one-time expectation for GetAuthenticatedSession
func (m *MockablePeer) OnGetAuthenticatedSessionOnce(identityKey string, maxWaitTime int, session *auth.PeerSession, err error) *mock.Call {
	return m.On("GetAuthenticatedSession", identityKey, maxWaitTime).Return(session, err).Once()
}

// OnSendCertificateResponseOnce sets up a one-time expectation for SendCertificateResponse
func (m *MockablePeer) OnSendCertificateResponseOnce(verifierIdentityKey string, certificates []certificates.VerifiableCertificate, err error) *mock.Call {
	return m.On("SendCertificateResponse", verifierIdentityKey, certificates).Return(err).Once()
}

// OnListenForGeneralMessagesOnce sets up a one-time expectation for ListenForGeneralMessages
func (m *MockablePeer) OnListenForGeneralMessagesOnce(callbackID int) *mock.Call {
	return m.On("ListenForGeneralMessages", mock.Anything).Return(callbackID).Once()
}

// OnStopListeningForGeneralMessagesOnce sets up a one-time expectation for StopListeningForGeneralMessages
func (m *MockablePeer) OnStopListeningForGeneralMessagesOnce(callbackID int) *mock.Call {
	return m.On("StopListeningForGeneralMessages", callbackID).Once()
}

// OnListenForCertificatesReceivedOnce sets up a one-time expectation for ListenForCertificatesReceived
func (m *MockablePeer) OnListenForCertificatesReceivedOnce(callbackID int) *mock.Call {
	return m.On("ListenForCertificatesReceived", mock.Anything).Return(callbackID).Once()
}

// OnStopListeningForCertificatesReceivedOnce sets up a one-time expectation for StopListeningForCertificatesReceived
func (m *MockablePeer) OnStopListeningForCertificatesReceivedOnce(callbackID int) *mock.Call {
	return m.On("StopListeningForCertificatesReceived", callbackID).Once()
}

// OnListenForCertificatesRequestedOnce sets up a one-time expectation for ListenForCertificatesRequested
func (m *MockablePeer) OnListenForCertificatesRequestedOnce(callbackID int) *mock.Call {
	return m.On("ListenForCertificatesRequested", mock.Anything).Return(callbackID).Once()
}

// OnStopListeningForCertificatesRequestedOnce sets up a one-time expectation for StopListeningForCertificatesRequested
func (m *MockablePeer) OnStopListeningForCertificatesRequestedOnce(callbackID int) *mock.Call {
	return m.On("StopListeningForCertificatesRequested", callbackID).Once()
}

// SimulateIncomingGeneralMessage provides a helper to simulate callbacks for testing
func (m *MockablePeer) SimulateIncomingGeneralMessage(senderPublicKey string, payload []byte, callback func(string, []byte)) {
	callback(senderPublicKey, payload)
}

// SimulateIncomingCertificates provides a helper to simulate callbacks for testing
func (m *MockablePeer) SimulateIncomingCertificates(senderPublicKey string, certificates []certificates.VerifiableCertificate, callback func(string, []certificates.VerifiableCertificate)) {
	callback(senderPublicKey, certificates)
}

// SimulateIncomingCertificateRequest provides a helper to simulate callbacks for testing
func (m *MockablePeer) SimulateIncomingCertificateRequest(senderPublicKey string, request sdkUtils.RequestedCertificateSet, callback func(string, sdkUtils.RequestedCertificateSet)) {
	callback(senderPublicKey, request)
}
