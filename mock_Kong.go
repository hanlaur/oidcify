// Code generated by mockery v2.53.3. DO NOT EDIT.

package main

import (
	client "github.com/Kong/go-pdk/client"
	entities "github.com/Kong/go-pdk/entities"

	mock "github.com/stretchr/testify/mock"
)

// MockKong is an autogenerated mock type for the Kong type
type MockKong struct {
	mock.Mock
}

type MockKong_Expecter struct {
	mock *mock.Mock
}

func (_m *MockKong) EXPECT() *MockKong_Expecter {
	return &MockKong_Expecter{mock: &_m.Mock}
}

// ClientAuthenticate provides a mock function with given fields: consumer, credential
func (_m *MockKong) ClientAuthenticate(consumer *entities.Consumer, credential *client.AuthenticatedCredential) error {
	ret := _m.Called(consumer, credential)

	if len(ret) == 0 {
		panic("no return value specified for ClientAuthenticate")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*entities.Consumer, *client.AuthenticatedCredential) error); ok {
		r0 = rf(consumer, credential)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockKong_ClientAuthenticate_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ClientAuthenticate'
type MockKong_ClientAuthenticate_Call struct {
	*mock.Call
}

// ClientAuthenticate is a helper method to define mock.On call
//   - consumer *entities.Consumer
//   - credential *client.AuthenticatedCredential
func (_e *MockKong_Expecter) ClientAuthenticate(consumer interface{}, credential interface{}) *MockKong_ClientAuthenticate_Call {
	return &MockKong_ClientAuthenticate_Call{Call: _e.mock.On("ClientAuthenticate", consumer, credential)}
}

func (_c *MockKong_ClientAuthenticate_Call) Run(run func(consumer *entities.Consumer, credential *client.AuthenticatedCredential)) *MockKong_ClientAuthenticate_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*entities.Consumer), args[1].(*client.AuthenticatedCredential))
	})
	return _c
}

func (_c *MockKong_ClientAuthenticate_Call) Return(_a0 error) *MockKong_ClientAuthenticate_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockKong_ClientAuthenticate_Call) RunAndReturn(run func(*entities.Consumer, *client.AuthenticatedCredential) error) *MockKong_ClientAuthenticate_Call {
	_c.Call.Return(run)
	return _c
}

// ClientGetCredential provides a mock function with no fields
func (_m *MockKong) ClientGetCredential() (client.AuthenticatedCredential, error) {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for ClientGetCredential")
	}

	var r0 client.AuthenticatedCredential
	var r1 error
	if rf, ok := ret.Get(0).(func() (client.AuthenticatedCredential, error)); ok {
		return rf()
	}
	if rf, ok := ret.Get(0).(func() client.AuthenticatedCredential); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(client.AuthenticatedCredential)
	}

	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockKong_ClientGetCredential_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ClientGetCredential'
type MockKong_ClientGetCredential_Call struct {
	*mock.Call
}

// ClientGetCredential is a helper method to define mock.On call
func (_e *MockKong_Expecter) ClientGetCredential() *MockKong_ClientGetCredential_Call {
	return &MockKong_ClientGetCredential_Call{Call: _e.mock.On("ClientGetCredential")}
}

func (_c *MockKong_ClientGetCredential_Call) Run(run func()) *MockKong_ClientGetCredential_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockKong_ClientGetCredential_Call) Return(_a0 client.AuthenticatedCredential, _a1 error) *MockKong_ClientGetCredential_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockKong_ClientGetCredential_Call) RunAndReturn(run func() (client.AuthenticatedCredential, error)) *MockKong_ClientGetCredential_Call {
	_c.Call.Return(run)
	return _c
}

// ClientLoadConsumer provides a mock function with given fields: consumerID, byUsername
func (_m *MockKong) ClientLoadConsumer(consumerID string, byUsername bool) (entities.Consumer, error) {
	ret := _m.Called(consumerID, byUsername)

	if len(ret) == 0 {
		panic("no return value specified for ClientLoadConsumer")
	}

	var r0 entities.Consumer
	var r1 error
	if rf, ok := ret.Get(0).(func(string, bool) (entities.Consumer, error)); ok {
		return rf(consumerID, byUsername)
	}
	if rf, ok := ret.Get(0).(func(string, bool) entities.Consumer); ok {
		r0 = rf(consumerID, byUsername)
	} else {
		r0 = ret.Get(0).(entities.Consumer)
	}

	if rf, ok := ret.Get(1).(func(string, bool) error); ok {
		r1 = rf(consumerID, byUsername)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockKong_ClientLoadConsumer_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ClientLoadConsumer'
type MockKong_ClientLoadConsumer_Call struct {
	*mock.Call
}

// ClientLoadConsumer is a helper method to define mock.On call
//   - consumerID string
//   - byUsername bool
func (_e *MockKong_Expecter) ClientLoadConsumer(consumerID interface{}, byUsername interface{}) *MockKong_ClientLoadConsumer_Call {
	return &MockKong_ClientLoadConsumer_Call{Call: _e.mock.On("ClientLoadConsumer", consumerID, byUsername)}
}

func (_c *MockKong_ClientLoadConsumer_Call) Run(run func(consumerID string, byUsername bool)) *MockKong_ClientLoadConsumer_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(bool))
	})
	return _c
}

func (_c *MockKong_ClientLoadConsumer_Call) Return(_a0 entities.Consumer, _a1 error) *MockKong_ClientLoadConsumer_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockKong_ClientLoadConsumer_Call) RunAndReturn(run func(string, bool) (entities.Consumer, error)) *MockKong_ClientLoadConsumer_Call {
	_c.Call.Return(run)
	return _c
}

// CtxSetShared provides a mock function with given fields: k, value
func (_m *MockKong) CtxSetShared(k string, value interface{}) error {
	ret := _m.Called(k, value)

	if len(ret) == 0 {
		panic("no return value specified for CtxSetShared")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(string, interface{}) error); ok {
		r0 = rf(k, value)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockKong_CtxSetShared_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CtxSetShared'
type MockKong_CtxSetShared_Call struct {
	*mock.Call
}

// CtxSetShared is a helper method to define mock.On call
//   - k string
//   - value interface{}
func (_e *MockKong_Expecter) CtxSetShared(k interface{}, value interface{}) *MockKong_CtxSetShared_Call {
	return &MockKong_CtxSetShared_Call{Call: _e.mock.On("CtxSetShared", k, value)}
}

func (_c *MockKong_CtxSetShared_Call) Run(run func(k string, value interface{})) *MockKong_CtxSetShared_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(interface{}))
	})
	return _c
}

func (_c *MockKong_CtxSetShared_Call) Return(_a0 error) *MockKong_CtxSetShared_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockKong_CtxSetShared_Call) RunAndReturn(run func(string, interface{}) error) *MockKong_CtxSetShared_Call {
	_c.Call.Return(run)
	return _c
}

// LogAlert provides a mock function with given fields: args
func (_m *MockKong) LogAlert(args ...interface{}) error {
	var _ca []interface{}
	_ca = append(_ca, args...)
	ret := _m.Called(_ca...)

	if len(ret) == 0 {
		panic("no return value specified for LogAlert")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(...interface{}) error); ok {
		r0 = rf(args...)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockKong_LogAlert_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'LogAlert'
type MockKong_LogAlert_Call struct {
	*mock.Call
}

// LogAlert is a helper method to define mock.On call
//   - args ...interface{}
func (_e *MockKong_Expecter) LogAlert(args ...interface{}) *MockKong_LogAlert_Call {
	return &MockKong_LogAlert_Call{Call: _e.mock.On("LogAlert",
		append([]interface{}{}, args...)...)}
}

func (_c *MockKong_LogAlert_Call) Run(run func(args ...interface{})) *MockKong_LogAlert_Call {
	_c.Call.Run(func(args mock.Arguments) {
		variadicArgs := make([]interface{}, len(args)-0)
		for i, a := range args[0:] {
			if a != nil {
				variadicArgs[i] = a.(interface{})
			}
		}
		run(variadicArgs...)
	})
	return _c
}

func (_c *MockKong_LogAlert_Call) Return(_a0 error) *MockKong_LogAlert_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockKong_LogAlert_Call) RunAndReturn(run func(...interface{}) error) *MockKong_LogAlert_Call {
	_c.Call.Return(run)
	return _c
}

// LogCrit provides a mock function with given fields: args
func (_m *MockKong) LogCrit(args ...interface{}) error {
	var _ca []interface{}
	_ca = append(_ca, args...)
	ret := _m.Called(_ca...)

	if len(ret) == 0 {
		panic("no return value specified for LogCrit")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(...interface{}) error); ok {
		r0 = rf(args...)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockKong_LogCrit_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'LogCrit'
type MockKong_LogCrit_Call struct {
	*mock.Call
}

// LogCrit is a helper method to define mock.On call
//   - args ...interface{}
func (_e *MockKong_Expecter) LogCrit(args ...interface{}) *MockKong_LogCrit_Call {
	return &MockKong_LogCrit_Call{Call: _e.mock.On("LogCrit",
		append([]interface{}{}, args...)...)}
}

func (_c *MockKong_LogCrit_Call) Run(run func(args ...interface{})) *MockKong_LogCrit_Call {
	_c.Call.Run(func(args mock.Arguments) {
		variadicArgs := make([]interface{}, len(args)-0)
		for i, a := range args[0:] {
			if a != nil {
				variadicArgs[i] = a.(interface{})
			}
		}
		run(variadicArgs...)
	})
	return _c
}

func (_c *MockKong_LogCrit_Call) Return(_a0 error) *MockKong_LogCrit_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockKong_LogCrit_Call) RunAndReturn(run func(...interface{}) error) *MockKong_LogCrit_Call {
	_c.Call.Return(run)
	return _c
}

// LogDebug provides a mock function with given fields: args
func (_m *MockKong) LogDebug(args ...interface{}) error {
	var _ca []interface{}
	_ca = append(_ca, args...)
	ret := _m.Called(_ca...)

	if len(ret) == 0 {
		panic("no return value specified for LogDebug")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(...interface{}) error); ok {
		r0 = rf(args...)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockKong_LogDebug_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'LogDebug'
type MockKong_LogDebug_Call struct {
	*mock.Call
}

// LogDebug is a helper method to define mock.On call
//   - args ...interface{}
func (_e *MockKong_Expecter) LogDebug(args ...interface{}) *MockKong_LogDebug_Call {
	return &MockKong_LogDebug_Call{Call: _e.mock.On("LogDebug",
		append([]interface{}{}, args...)...)}
}

func (_c *MockKong_LogDebug_Call) Run(run func(args ...interface{})) *MockKong_LogDebug_Call {
	_c.Call.Run(func(args mock.Arguments) {
		variadicArgs := make([]interface{}, len(args)-0)
		for i, a := range args[0:] {
			if a != nil {
				variadicArgs[i] = a.(interface{})
			}
		}
		run(variadicArgs...)
	})
	return _c
}

func (_c *MockKong_LogDebug_Call) Return(_a0 error) *MockKong_LogDebug_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockKong_LogDebug_Call) RunAndReturn(run func(...interface{}) error) *MockKong_LogDebug_Call {
	_c.Call.Return(run)
	return _c
}

// LogErr provides a mock function with given fields: args
func (_m *MockKong) LogErr(args ...interface{}) error {
	var _ca []interface{}
	_ca = append(_ca, args...)
	ret := _m.Called(_ca...)

	if len(ret) == 0 {
		panic("no return value specified for LogErr")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(...interface{}) error); ok {
		r0 = rf(args...)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockKong_LogErr_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'LogErr'
type MockKong_LogErr_Call struct {
	*mock.Call
}

// LogErr is a helper method to define mock.On call
//   - args ...interface{}
func (_e *MockKong_Expecter) LogErr(args ...interface{}) *MockKong_LogErr_Call {
	return &MockKong_LogErr_Call{Call: _e.mock.On("LogErr",
		append([]interface{}{}, args...)...)}
}

func (_c *MockKong_LogErr_Call) Run(run func(args ...interface{})) *MockKong_LogErr_Call {
	_c.Call.Run(func(args mock.Arguments) {
		variadicArgs := make([]interface{}, len(args)-0)
		for i, a := range args[0:] {
			if a != nil {
				variadicArgs[i] = a.(interface{})
			}
		}
		run(variadicArgs...)
	})
	return _c
}

func (_c *MockKong_LogErr_Call) Return(_a0 error) *MockKong_LogErr_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockKong_LogErr_Call) RunAndReturn(run func(...interface{}) error) *MockKong_LogErr_Call {
	_c.Call.Return(run)
	return _c
}

// LogInfo provides a mock function with given fields: args
func (_m *MockKong) LogInfo(args ...interface{}) error {
	var _ca []interface{}
	_ca = append(_ca, args...)
	ret := _m.Called(_ca...)

	if len(ret) == 0 {
		panic("no return value specified for LogInfo")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(...interface{}) error); ok {
		r0 = rf(args...)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockKong_LogInfo_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'LogInfo'
type MockKong_LogInfo_Call struct {
	*mock.Call
}

// LogInfo is a helper method to define mock.On call
//   - args ...interface{}
func (_e *MockKong_Expecter) LogInfo(args ...interface{}) *MockKong_LogInfo_Call {
	return &MockKong_LogInfo_Call{Call: _e.mock.On("LogInfo",
		append([]interface{}{}, args...)...)}
}

func (_c *MockKong_LogInfo_Call) Run(run func(args ...interface{})) *MockKong_LogInfo_Call {
	_c.Call.Run(func(args mock.Arguments) {
		variadicArgs := make([]interface{}, len(args)-0)
		for i, a := range args[0:] {
			if a != nil {
				variadicArgs[i] = a.(interface{})
			}
		}
		run(variadicArgs...)
	})
	return _c
}

func (_c *MockKong_LogInfo_Call) Return(_a0 error) *MockKong_LogInfo_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockKong_LogInfo_Call) RunAndReturn(run func(...interface{}) error) *MockKong_LogInfo_Call {
	_c.Call.Return(run)
	return _c
}

// LogNotice provides a mock function with given fields: args
func (_m *MockKong) LogNotice(args ...interface{}) error {
	var _ca []interface{}
	_ca = append(_ca, args...)
	ret := _m.Called(_ca...)

	if len(ret) == 0 {
		panic("no return value specified for LogNotice")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(...interface{}) error); ok {
		r0 = rf(args...)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockKong_LogNotice_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'LogNotice'
type MockKong_LogNotice_Call struct {
	*mock.Call
}

// LogNotice is a helper method to define mock.On call
//   - args ...interface{}
func (_e *MockKong_Expecter) LogNotice(args ...interface{}) *MockKong_LogNotice_Call {
	return &MockKong_LogNotice_Call{Call: _e.mock.On("LogNotice",
		append([]interface{}{}, args...)...)}
}

func (_c *MockKong_LogNotice_Call) Run(run func(args ...interface{})) *MockKong_LogNotice_Call {
	_c.Call.Run(func(args mock.Arguments) {
		variadicArgs := make([]interface{}, len(args)-0)
		for i, a := range args[0:] {
			if a != nil {
				variadicArgs[i] = a.(interface{})
			}
		}
		run(variadicArgs...)
	})
	return _c
}

func (_c *MockKong_LogNotice_Call) Return(_a0 error) *MockKong_LogNotice_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockKong_LogNotice_Call) RunAndReturn(run func(...interface{}) error) *MockKong_LogNotice_Call {
	_c.Call.Return(run)
	return _c
}

// LogWarn provides a mock function with given fields: args
func (_m *MockKong) LogWarn(args ...interface{}) error {
	var _ca []interface{}
	_ca = append(_ca, args...)
	ret := _m.Called(_ca...)

	if len(ret) == 0 {
		panic("no return value specified for LogWarn")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(...interface{}) error); ok {
		r0 = rf(args...)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockKong_LogWarn_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'LogWarn'
type MockKong_LogWarn_Call struct {
	*mock.Call
}

// LogWarn is a helper method to define mock.On call
//   - args ...interface{}
func (_e *MockKong_Expecter) LogWarn(args ...interface{}) *MockKong_LogWarn_Call {
	return &MockKong_LogWarn_Call{Call: _e.mock.On("LogWarn",
		append([]interface{}{}, args...)...)}
}

func (_c *MockKong_LogWarn_Call) Run(run func(args ...interface{})) *MockKong_LogWarn_Call {
	_c.Call.Run(func(args mock.Arguments) {
		variadicArgs := make([]interface{}, len(args)-0)
		for i, a := range args[0:] {
			if a != nil {
				variadicArgs[i] = a.(interface{})
			}
		}
		run(variadicArgs...)
	})
	return _c
}

func (_c *MockKong_LogWarn_Call) Return(_a0 error) *MockKong_LogWarn_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockKong_LogWarn_Call) RunAndReturn(run func(...interface{}) error) *MockKong_LogWarn_Call {
	_c.Call.Return(run)
	return _c
}

// RequestGetHeader provides a mock function with given fields: k
func (_m *MockKong) RequestGetHeader(k string) (string, error) {
	ret := _m.Called(k)

	if len(ret) == 0 {
		panic("no return value specified for RequestGetHeader")
	}

	var r0 string
	var r1 error
	if rf, ok := ret.Get(0).(func(string) (string, error)); ok {
		return rf(k)
	}
	if rf, ok := ret.Get(0).(func(string) string); ok {
		r0 = rf(k)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(k)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockKong_RequestGetHeader_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RequestGetHeader'
type MockKong_RequestGetHeader_Call struct {
	*mock.Call
}

// RequestGetHeader is a helper method to define mock.On call
//   - k string
func (_e *MockKong_Expecter) RequestGetHeader(k interface{}) *MockKong_RequestGetHeader_Call {
	return &MockKong_RequestGetHeader_Call{Call: _e.mock.On("RequestGetHeader", k)}
}

func (_c *MockKong_RequestGetHeader_Call) Run(run func(k string)) *MockKong_RequestGetHeader_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *MockKong_RequestGetHeader_Call) Return(_a0 string, _a1 error) *MockKong_RequestGetHeader_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockKong_RequestGetHeader_Call) RunAndReturn(run func(string) (string, error)) *MockKong_RequestGetHeader_Call {
	_c.Call.Return(run)
	return _c
}

// RequestGetHeaders provides a mock function with given fields: maxHeaders
func (_m *MockKong) RequestGetHeaders(maxHeaders int) (map[string][]string, error) {
	ret := _m.Called(maxHeaders)

	if len(ret) == 0 {
		panic("no return value specified for RequestGetHeaders")
	}

	var r0 map[string][]string
	var r1 error
	if rf, ok := ret.Get(0).(func(int) (map[string][]string, error)); ok {
		return rf(maxHeaders)
	}
	if rf, ok := ret.Get(0).(func(int) map[string][]string); ok {
		r0 = rf(maxHeaders)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(map[string][]string)
		}
	}

	if rf, ok := ret.Get(1).(func(int) error); ok {
		r1 = rf(maxHeaders)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockKong_RequestGetHeaders_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RequestGetHeaders'
type MockKong_RequestGetHeaders_Call struct {
	*mock.Call
}

// RequestGetHeaders is a helper method to define mock.On call
//   - maxHeaders int
func (_e *MockKong_Expecter) RequestGetHeaders(maxHeaders interface{}) *MockKong_RequestGetHeaders_Call {
	return &MockKong_RequestGetHeaders_Call{Call: _e.mock.On("RequestGetHeaders", maxHeaders)}
}

func (_c *MockKong_RequestGetHeaders_Call) Run(run func(maxHeaders int)) *MockKong_RequestGetHeaders_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(int))
	})
	return _c
}

func (_c *MockKong_RequestGetHeaders_Call) Return(_a0 map[string][]string, _a1 error) *MockKong_RequestGetHeaders_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockKong_RequestGetHeaders_Call) RunAndReturn(run func(int) (map[string][]string, error)) *MockKong_RequestGetHeaders_Call {
	_c.Call.Return(run)
	return _c
}

// RequestGetPathWithQuery provides a mock function with no fields
func (_m *MockKong) RequestGetPathWithQuery() (string, error) {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for RequestGetPathWithQuery")
	}

	var r0 string
	var r1 error
	if rf, ok := ret.Get(0).(func() (string, error)); ok {
		return rf()
	}
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockKong_RequestGetPathWithQuery_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RequestGetPathWithQuery'
type MockKong_RequestGetPathWithQuery_Call struct {
	*mock.Call
}

// RequestGetPathWithQuery is a helper method to define mock.On call
func (_e *MockKong_Expecter) RequestGetPathWithQuery() *MockKong_RequestGetPathWithQuery_Call {
	return &MockKong_RequestGetPathWithQuery_Call{Call: _e.mock.On("RequestGetPathWithQuery")}
}

func (_c *MockKong_RequestGetPathWithQuery_Call) Run(run func()) *MockKong_RequestGetPathWithQuery_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockKong_RequestGetPathWithQuery_Call) Return(_a0 string, _a1 error) *MockKong_RequestGetPathWithQuery_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockKong_RequestGetPathWithQuery_Call) RunAndReturn(run func() (string, error)) *MockKong_RequestGetPathWithQuery_Call {
	_c.Call.Return(run)
	return _c
}

// RequestGetQueryArg provides a mock function with given fields: k
func (_m *MockKong) RequestGetQueryArg(k string) (string, error) {
	ret := _m.Called(k)

	if len(ret) == 0 {
		panic("no return value specified for RequestGetQueryArg")
	}

	var r0 string
	var r1 error
	if rf, ok := ret.Get(0).(func(string) (string, error)); ok {
		return rf(k)
	}
	if rf, ok := ret.Get(0).(func(string) string); ok {
		r0 = rf(k)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(k)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockKong_RequestGetQueryArg_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RequestGetQueryArg'
type MockKong_RequestGetQueryArg_Call struct {
	*mock.Call
}

// RequestGetQueryArg is a helper method to define mock.On call
//   - k string
func (_e *MockKong_Expecter) RequestGetQueryArg(k interface{}) *MockKong_RequestGetQueryArg_Call {
	return &MockKong_RequestGetQueryArg_Call{Call: _e.mock.On("RequestGetQueryArg", k)}
}

func (_c *MockKong_RequestGetQueryArg_Call) Run(run func(k string)) *MockKong_RequestGetQueryArg_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *MockKong_RequestGetQueryArg_Call) Return(_a0 string, _a1 error) *MockKong_RequestGetQueryArg_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockKong_RequestGetQueryArg_Call) RunAndReturn(run func(string) (string, error)) *MockKong_RequestGetQueryArg_Call {
	_c.Call.Return(run)
	return _c
}

// ResponseAddHeader provides a mock function with given fields: k, v
func (_m *MockKong) ResponseAddHeader(k string, v string) error {
	ret := _m.Called(k, v)

	if len(ret) == 0 {
		panic("no return value specified for ResponseAddHeader")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(string, string) error); ok {
		r0 = rf(k, v)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockKong_ResponseAddHeader_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ResponseAddHeader'
type MockKong_ResponseAddHeader_Call struct {
	*mock.Call
}

// ResponseAddHeader is a helper method to define mock.On call
//   - k string
//   - v string
func (_e *MockKong_Expecter) ResponseAddHeader(k interface{}, v interface{}) *MockKong_ResponseAddHeader_Call {
	return &MockKong_ResponseAddHeader_Call{Call: _e.mock.On("ResponseAddHeader", k, v)}
}

func (_c *MockKong_ResponseAddHeader_Call) Run(run func(k string, v string)) *MockKong_ResponseAddHeader_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(string))
	})
	return _c
}

func (_c *MockKong_ResponseAddHeader_Call) Return(_a0 error) *MockKong_ResponseAddHeader_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockKong_ResponseAddHeader_Call) RunAndReturn(run func(string, string) error) *MockKong_ResponseAddHeader_Call {
	_c.Call.Return(run)
	return _c
}

// ResponseExit provides a mock function with given fields: status, body, headers
func (_m *MockKong) ResponseExit(status int, body []byte, headers map[string][]string) {
	_m.Called(status, body, headers)
}

// MockKong_ResponseExit_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ResponseExit'
type MockKong_ResponseExit_Call struct {
	*mock.Call
}

// ResponseExit is a helper method to define mock.On call
//   - status int
//   - body []byte
//   - headers map[string][]string
func (_e *MockKong_Expecter) ResponseExit(status interface{}, body interface{}, headers interface{}) *MockKong_ResponseExit_Call {
	return &MockKong_ResponseExit_Call{Call: _e.mock.On("ResponseExit", status, body, headers)}
}

func (_c *MockKong_ResponseExit_Call) Run(run func(status int, body []byte, headers map[string][]string)) *MockKong_ResponseExit_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(int), args[1].([]byte), args[2].(map[string][]string))
	})
	return _c
}

func (_c *MockKong_ResponseExit_Call) Return() *MockKong_ResponseExit_Call {
	_c.Call.Return()
	return _c
}

func (_c *MockKong_ResponseExit_Call) RunAndReturn(run func(int, []byte, map[string][]string)) *MockKong_ResponseExit_Call {
	_c.Run(run)
	return _c
}

// ResponseExitStatus provides a mock function with given fields: status
func (_m *MockKong) ResponseExitStatus(status int) {
	_m.Called(status)
}

// MockKong_ResponseExitStatus_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ResponseExitStatus'
type MockKong_ResponseExitStatus_Call struct {
	*mock.Call
}

// ResponseExitStatus is a helper method to define mock.On call
//   - status int
func (_e *MockKong_Expecter) ResponseExitStatus(status interface{}) *MockKong_ResponseExitStatus_Call {
	return &MockKong_ResponseExitStatus_Call{Call: _e.mock.On("ResponseExitStatus", status)}
}

func (_c *MockKong_ResponseExitStatus_Call) Run(run func(status int)) *MockKong_ResponseExitStatus_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(int))
	})
	return _c
}

func (_c *MockKong_ResponseExitStatus_Call) Return() *MockKong_ResponseExitStatus_Call {
	_c.Call.Return()
	return _c
}

func (_c *MockKong_ResponseExitStatus_Call) RunAndReturn(run func(int)) *MockKong_ResponseExitStatus_Call {
	_c.Run(run)
	return _c
}

// ResponseSetHeader provides a mock function with given fields: k, v
func (_m *MockKong) ResponseSetHeader(k string, v string) error {
	ret := _m.Called(k, v)

	if len(ret) == 0 {
		panic("no return value specified for ResponseSetHeader")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(string, string) error); ok {
		r0 = rf(k, v)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockKong_ResponseSetHeader_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ResponseSetHeader'
type MockKong_ResponseSetHeader_Call struct {
	*mock.Call
}

// ResponseSetHeader is a helper method to define mock.On call
//   - k string
//   - v string
func (_e *MockKong_Expecter) ResponseSetHeader(k interface{}, v interface{}) *MockKong_ResponseSetHeader_Call {
	return &MockKong_ResponseSetHeader_Call{Call: _e.mock.On("ResponseSetHeader", k, v)}
}

func (_c *MockKong_ResponseSetHeader_Call) Run(run func(k string, v string)) *MockKong_ResponseSetHeader_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(string))
	})
	return _c
}

func (_c *MockKong_ResponseSetHeader_Call) Return(_a0 error) *MockKong_ResponseSetHeader_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockKong_ResponseSetHeader_Call) RunAndReturn(run func(string, string) error) *MockKong_ResponseSetHeader_Call {
	_c.Call.Return(run)
	return _c
}

// ServiceRequestClearHeader provides a mock function with given fields: name
func (_m *MockKong) ServiceRequestClearHeader(name string) error {
	ret := _m.Called(name)

	if len(ret) == 0 {
		panic("no return value specified for ServiceRequestClearHeader")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(name)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockKong_ServiceRequestClearHeader_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ServiceRequestClearHeader'
type MockKong_ServiceRequestClearHeader_Call struct {
	*mock.Call
}

// ServiceRequestClearHeader is a helper method to define mock.On call
//   - name string
func (_e *MockKong_Expecter) ServiceRequestClearHeader(name interface{}) *MockKong_ServiceRequestClearHeader_Call {
	return &MockKong_ServiceRequestClearHeader_Call{Call: _e.mock.On("ServiceRequestClearHeader", name)}
}

func (_c *MockKong_ServiceRequestClearHeader_Call) Run(run func(name string)) *MockKong_ServiceRequestClearHeader_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *MockKong_ServiceRequestClearHeader_Call) Return(_a0 error) *MockKong_ServiceRequestClearHeader_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockKong_ServiceRequestClearHeader_Call) RunAndReturn(run func(string) error) *MockKong_ServiceRequestClearHeader_Call {
	_c.Call.Return(run)
	return _c
}

// ServiceRequestSetHeader provides a mock function with given fields: name, value
func (_m *MockKong) ServiceRequestSetHeader(name string, value string) error {
	ret := _m.Called(name, value)

	if len(ret) == 0 {
		panic("no return value specified for ServiceRequestSetHeader")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(string, string) error); ok {
		r0 = rf(name, value)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockKong_ServiceRequestSetHeader_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ServiceRequestSetHeader'
type MockKong_ServiceRequestSetHeader_Call struct {
	*mock.Call
}

// ServiceRequestSetHeader is a helper method to define mock.On call
//   - name string
//   - value string
func (_e *MockKong_Expecter) ServiceRequestSetHeader(name interface{}, value interface{}) *MockKong_ServiceRequestSetHeader_Call {
	return &MockKong_ServiceRequestSetHeader_Call{Call: _e.mock.On("ServiceRequestSetHeader", name, value)}
}

func (_c *MockKong_ServiceRequestSetHeader_Call) Run(run func(name string, value string)) *MockKong_ServiceRequestSetHeader_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(string))
	})
	return _c
}

func (_c *MockKong_ServiceRequestSetHeader_Call) Return(_a0 error) *MockKong_ServiceRequestSetHeader_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockKong_ServiceRequestSetHeader_Call) RunAndReturn(run func(string, string) error) *MockKong_ServiceRequestSetHeader_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockKong creates a new instance of MockKong. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockKong(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockKong {
	mock := &MockKong{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
