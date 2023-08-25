// Code generated by MockGen. DO NOT EDIT.
// Source: ./interfaces.go

// Package sbom is a generated GoMock package.
package sbom

import (
	context "context"
	http "net/http"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
)

// MockSbomClient is a mock of SbomClient interface.
type MockSbomClient struct {
	ctrl     *gomock.Controller
	recorder *MockSbomClientMockRecorder
}

// MockSbomClientMockRecorder is the mock recorder for MockSbomClient.
type MockSbomClientMockRecorder struct {
	mock *MockSbomClient
}

// NewMockSbomClient creates a new mock instance.
func NewMockSbomClient(ctrl *gomock.Controller) *MockSbomClient {
	mock := &MockSbomClient{ctrl: ctrl}
	mock.recorder = &MockSbomClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockSbomClient) EXPECT() *MockSbomClientMockRecorder {
	return m.recorder
}

// GetSbomForDepGraph mocks base method.
func (m *MockSbomClient) GetSbomForDepGraph(arg0 context.Context, arg1, arg2 string, arg3 *GetSbomForDepGraphRequest) (*GetSbomForDepGraphResult, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetSbomForDepGraph", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(*GetSbomForDepGraphResult)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetSbomForDepGraph indicates an expected call of GetSbomForDepGraph.
func (mr *MockSbomClientMockRecorder) GetSbomForDepGraph(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetSbomForDepGraph", reflect.TypeOf((*MockSbomClient)(nil).GetSbomForDepGraph), arg0, arg1, arg2, arg3)
}

// MockHTTPClient is a mock of HTTPClient interface.
type MockHTTPClient struct {
	ctrl     *gomock.Controller
	recorder *MockHTTPClientMockRecorder
}

// MockHTTPClientMockRecorder is the mock recorder for MockHTTPClient.
type MockHTTPClientMockRecorder struct {
	mock *MockHTTPClient
}

// NewMockHTTPClient creates a new mock instance.
func NewMockHTTPClient(ctrl *gomock.Controller) *MockHTTPClient {
	mock := &MockHTTPClient{ctrl: ctrl}
	mock.recorder = &MockHTTPClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockHTTPClient) EXPECT() *MockHTTPClientMockRecorder {
	return m.recorder
}

// Do mocks base method.
func (m *MockHTTPClient) Do(arg0 *http.Request) (*http.Response, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Do", arg0)
	ret0, _ := ret[0].(*http.Response)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Do indicates an expected call of Do.
func (mr *MockHTTPClientMockRecorder) Do(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Do", reflect.TypeOf((*MockHTTPClient)(nil).Do), arg0)
}
