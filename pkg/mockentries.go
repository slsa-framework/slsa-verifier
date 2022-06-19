package pkg

import (
	reflect "reflect"

	runtime "github.com/go-openapi/runtime"
	gomock "github.com/golang/mock/gomock"
	entries "github.com/sigstore/rekor/pkg/generated/client/entries"
)

// MockEntriesClientService is a mock of ClientService interface.
type MockEntriesClientService struct {
	ctrl     *gomock.Controller
	recorder *MockEntriesClientServiceMockRecorder
}

// MockEntriesClientServiceMockRecorder is the mock recorder for MockEntriesClientService.
type MockEntriesClientServiceMockRecorder struct {
	mock *MockEntriesClientService
}

// NewMockEntriesClientService creates a new mock instance.
func NewMockEntriesClientService(ctrl *gomock.Controller) *MockEntriesClientService {
	mock := &MockEntriesClientService{ctrl: ctrl}
	mock.recorder = &MockEntriesClientServiceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockEntriesClientService) EXPECT() *MockEntriesClientServiceMockRecorder {
	return m.recorder
}

// CreateLogEntry mocks base method.
func (m *MockEntriesClientService) CreateLogEntry(params *entries.CreateLogEntryParams, opts ...entries.ClientOption) (*entries.CreateLogEntryCreated, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{params}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "CreateLogEntry", varargs...)
	ret0, _ := ret[0].(*entries.CreateLogEntryCreated)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateLogEntry indicates an expected call of CreateLogEntry.
func (mr *MockEntriesClientServiceMockRecorder) CreateLogEntry(params interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{params}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateLogEntry", reflect.TypeOf((*MockEntriesClientService)(nil).CreateLogEntry), varargs...)
}

// GetLogEntryByIndex mocks base method.
func (m *MockEntriesClientService) GetLogEntryByIndex(params *entries.GetLogEntryByIndexParams, opts ...entries.ClientOption) (*entries.GetLogEntryByIndexOK, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{params}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetLogEntryByIndex", varargs...)
	ret0, _ := ret[0].(*entries.GetLogEntryByIndexOK)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetLogEntryByIndex indicates an expected call of GetLogEntryByIndex.
func (mr *MockEntriesClientServiceMockRecorder) GetLogEntryByIndex(params interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{params}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetLogEntryByIndex", reflect.TypeOf((*MockEntriesClientService)(nil).GetLogEntryByIndex), varargs...)
}

// GetLogEntryByUUID mocks base method.
func (m *MockEntriesClientService) GetLogEntryByUUID(params *entries.GetLogEntryByUUIDParams, opts ...entries.ClientOption) (*entries.GetLogEntryByUUIDOK, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{params}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetLogEntryByUUID", varargs...)
	ret0, _ := ret[0].(*entries.GetLogEntryByUUIDOK)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetLogEntryByUUID indicates an expected call of GetLogEntryByUUID.
func (mr *MockEntriesClientServiceMockRecorder) GetLogEntryByUUID(params interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{params}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetLogEntryByUUID", reflect.TypeOf((*MockEntriesClientService)(nil).GetLogEntryByUUID), varargs...)
}

// SearchLogQuery mocks base method.
func (m *MockEntriesClientService) SearchLogQuery(params *entries.SearchLogQueryParams, opts ...entries.ClientOption) (*entries.SearchLogQueryOK, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{params}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "SearchLogQuery", varargs...)
	ret0, _ := ret[0].(*entries.SearchLogQueryOK)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SearchLogQuery indicates an expected call of SearchLogQuery.
func (mr *MockEntriesClientServiceMockRecorder) SearchLogQuery(params interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{params}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SearchLogQuery", reflect.TypeOf((*MockEntriesClientService)(nil).SearchLogQuery), varargs...)
}

// SetTransport mocks base method.
func (m *MockEntriesClientService) SetTransport(transport runtime.ClientTransport) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SetTransport", transport)
}

// SetTransport indicates an expected call of SetTransport.
func (mr *MockEntriesClientServiceMockRecorder) SetTransport(transport interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetTransport", reflect.TypeOf((*MockEntriesClientService)(nil).SetTransport), transport)
}
