package pkg

import (
	reflect "reflect"

	runtime "github.com/go-openapi/runtime"
	gomock "github.com/golang/mock/gomock"
	"github.com/sigstore/rekor/pkg/generated/client/index"
)

// MockClientService is a mock of ClientService interface.
type MockClientService struct {
	ctrl     *gomock.Controller
	recorder *MockClientServiceMockRecorder
}

// MockClientServiceMockRecorder is the mock recorder for MockClientService.
type MockClientServiceMockRecorder struct {
	mock *MockClientService
}

// NewMockClientService creates a new mock instance.
func NewMockClientService(ctrl *gomock.Controller) *MockClientService {
	mock := &MockClientService{ctrl: ctrl}
	mock.recorder = &MockClientServiceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockClientService) EXPECT() *MockClientServiceMockRecorder {
	return m.recorder
}

// SearchIndex mocks base method.
func (m *MockClientService) SearchIndex(params *index.SearchIndexParams, opts ...index.ClientOption) (*index.SearchIndexOK, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{params}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "SearchIndex", varargs...)
	ret0, _ := ret[0].(*index.SearchIndexOK)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SearchIndex indicates an expected call of SearchIndex.
func (mr *MockClientServiceMockRecorder) SearchIndex(params interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{params}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SearchIndex", reflect.TypeOf((*MockClientService)(nil).SearchIndex), varargs...)
}

// SetTransport mocks base method.
func (m *MockClientService) SetTransport(transport runtime.ClientTransport) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SetTransport", transport)
}

// SetTransport indicates an expected call of SetTransport.
func (mr *MockClientServiceMockRecorder) SetTransport(transport interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetTransport", reflect.TypeOf((*MockClientService)(nil).SetTransport), transport)
}
