package mocks

import (
	"sync"

	"github.com/bsv-blockchain/go-sdk/auth"
	primitives "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/stretchr/testify/mock"
)

// MockableSessionManager is a mock implementation of the session manager interface
type MockableSessionManager struct {
	mock.Mock

	mu                    sync.Mutex
	sessions              map[string]auth.PeerSession
	identityKeyToSessions map[*primitives.PublicKey][]string
}

// NewMockableSessionManager creates a new instance of MockableSessionManager
func NewMockableSessionManager() *MockableSessionManager {
	return &MockableSessionManager{
		sessions:              make(map[string]auth.PeerSession),
		identityKeyToSessions: make(map[*primitives.PublicKey][]string),
	}
}

// AddSession return mocked value or add a session to the manager.
func (m *MockableSessionManager) AddSession(session *auth.PeerSession) error {
	if isExpectedMockCall(m.ExpectedCalls, "AddSession", session) {
		m.Called(session)
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if session.SessionNonce != "" {
		m.sessions[session.SessionNonce] = *session
	}
	if session.PeerIdentityKey != nil {
		sessionNonces, exists := m.identityKeyToSessions[session.PeerIdentityKey]
		if exists {
			m.identityKeyToSessions[session.PeerIdentityKey] = append(sessionNonces, session.SessionNonce)
			return nil
		}

		m.identityKeyToSessions[session.PeerIdentityKey] = []string{session.SessionNonce}
	}

	return nil
}

// UpdateSession return mocked value or update a session to the manager.
func (m *MockableSessionManager) UpdateSession(session *auth.PeerSession) {
	if isExpectedMockCall(m.ExpectedCalls, "UpdateSession", session) {
		m.Called(session)
		return
	}

	m.AddSession(session)
}

// GetSession return mocked value or get a session from the manager.
func (m *MockableSessionManager) GetSession(identifier string) (*auth.PeerSession, error) {
	if isExpectedMockCall(m.ExpectedCalls, "GetSession", identifier) {
		args := m.Called(identifier)
		if s, ok := args.Get(0).(*auth.PeerSession); ok {
			return s, args.Error(1)
		}
		return nil, args.Error(1)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if session, ok := m.sessions[identifier]; ok {
		return &session, nil
	}

	pk, err := primitives.PublicKeyFromString(identifier)
	if err != nil {
		return nil, err
	}

	if nonces, ok := m.identityKeyToSessions[pk]; ok && len(nonces) > 0 {
		if session, ok := m.sessions[nonces[0]]; ok {
			return &session, nil
		}
	}

	return nil, nil
}

// RemoveSession return mocked value or remove a session from the manager.
func (m *MockableSessionManager) RemoveSession(session *auth.PeerSession) {
	if isExpectedMockCall(m.ExpectedCalls, "RemoveSession", session) {
		m.Called(session)
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if session.SessionNonce != "" {
		delete(m.sessions, session.SessionNonce)
	}
	if session.PeerIdentityKey != nil {
		delete(m.identityKeyToSessions, session.PeerIdentityKey)
	}
}

// HasSession return mocked value or check if a session exists in the manager.
func (m *MockableSessionManager) HasSession(identifier string) bool {
	if isExpectedMockCall(m.ExpectedCalls, "HasSession", identifier) {
		args := m.Called(identifier)
		return args.Bool(0)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	pk, err := primitives.PublicKeyFromString(identifier)
	if err != nil {
		return false
	}

	_, existsNonce := m.sessions[identifier]
	nonces, existsIdentity := m.identityKeyToSessions[pk]
	return existsNonce || (existsIdentity && len(nonces) > 0)
}

// OnAddSessionOnce sets up a one-time expectation for the AddSession method.
func (m *MockableSessionManager) OnAddSessionOnce(session auth.PeerSession) *mock.Call {
	return m.On("AddSession", session).Once()
}

// OnUpdateSessionOnce sets up a one-time expectation for the UpdateSession method.
func (m *MockableSessionManager) OnUpdateSessionOnce(session auth.PeerSession) *mock.Call {
	return m.On("UpdateSession", session).Once()
}

// OnGetSessionOnce sets up a one-time expectation for the GetSession method.
func (m *MockableSessionManager) OnGetSessionOnce(identifier string, session *auth.PeerSession) *mock.Call {
	return m.On("GetSession", identifier).Return(session).Once()
}

// OnRemoveSessionOnce sets up a one-time expectation for the RemoveSession method.
func (m *MockableSessionManager) OnRemoveSessionOnce(session auth.PeerSession) *mock.Call {
	return m.On("RemoveSession", session).Once()
}

// OnHasSessionOnce sets up a one-time expectation for the HasSession method.
func (m *MockableSessionManager) OnHasSessionOnce(identifier string, exists bool) *mock.Call {
	return m.On("HasSession", identifier).Return(exists).Once()
}

// Clear clears all sessions and identity key mappings.
func (m *MockableSessionManager) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.sessions = make(map[string]auth.PeerSession)
	m.identityKeyToSessions = make(map[*primitives.PublicKey][]string)
}
