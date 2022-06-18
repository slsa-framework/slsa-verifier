package pkg

import (
	reflect "reflect"

	runtime "github.com/go-openapi/runtime"
	gomock "github.com/golang/mock/gomock"
	tlog "github.com/sigstore/rekor/pkg/generated/client/tlog"
)

// MockTlogClientService is a mock of ClientService interface.
type MockTlogClientService struct {
	ctrl     *gomock.Controller
	recorder *MockTlogClientServiceMockRecorder
}

// MockTlogClientServiceMockRecorder is the mock recorder for MockTlogClientService.
type MockTlogClientServiceMockRecorder struct {
	mock *MockTlogClientService
}

// NewMockTlogClientService creates a new mock instance.
func NewMockTlogClientService(ctrl *gomock.Controller) *MockTlogClientService {
	mock := &MockTlogClientService{ctrl: ctrl}
	mock.recorder = &MockTlogClientServiceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockTlogClientService) EXPECT() *MockTlogClientServiceMockRecorder {
	return m.recorder
}

// GetLogInfo mocks base method.
func (m *MockTlogClientService) GetLogInfo(params *tlog.GetLogInfoParams, opts ...tlog.ClientOption) (*tlog.GetLogInfoOK, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{params}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetLogInfo", varargs...)
	ret0, _ := ret[0].(*tlog.GetLogInfoOK)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetLogInfo indicates an expected call of GetLogInfo.
func (mr *MockTlogClientServiceMockRecorder) GetLogInfo(params interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{params}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetLogInfo", reflect.TypeOf((*MockTlogClientService)(nil).GetLogInfo), varargs...)
}

// GetLogProof mocks base method.
func (m *MockTlogClientService) GetLogProof(params *tlog.GetLogProofParams, opts ...tlog.ClientOption) (*tlog.GetLogProofOK, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{params}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetLogProof", varargs...)
	ret0, _ := ret[0].(*tlog.GetLogProofOK)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetLogProof indicates an expected call of GetLogProof.
func (mr *MockTlogClientServiceMockRecorder) GetLogProof(params interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{params}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetLogProof", reflect.TypeOf((*MockTlogClientService)(nil).GetLogProof), varargs...)
}

// SetTransport mocks base method.
func (m *MockTlogClientService) SetTransport(transport runtime.ClientTransport) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SetTransport", transport)
}

// SetTransport indicates an expected call of SetTransport.
func (mr *MockTlogClientServiceMockRecorder) SetTransport(transport interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetTransport", reflect.TypeOf((*MockTlogClientService)(nil).SetTransport), transport)
}
