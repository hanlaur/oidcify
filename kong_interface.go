//nolint:wrapcheck
package main

import (
	"github.com/Kong/go-pdk"
	"github.com/Kong/go-pdk/client"
	"github.com/Kong/go-pdk/entities"
)

// Kong interface wraps a subset of functions from Kong PDK used by the plugin.
// Intent is not to change the behavior of the functions, but to allow mocking of the PDK.
type Kong interface { //nolint:interfacebloat
	CtxSetShared(k string, value any) error

	LogAlert(args ...any) error
	LogCrit(args ...any) error
	LogErr(args ...any) error
	LogWarn(args ...any) error
	LogNotice(args ...any) error
	LogInfo(args ...any) error
	LogDebug(args ...any) error

	RequestGetPathWithQuery() (string, error)
	RequestGetHeader(k string) (string, error)
	RequestGetHeaders(maxHeaders int) (map[string][]string, error)
	RequestGetQueryArg(k string) (string, error)

	ResponseAddHeader(k string, v string) error
	ResponseExit(status int, body []byte, headers map[string][]string)
	ResponseExitStatus(status int)
	ResponseSetHeader(k string, v string) error

	ServiceRequestClearHeader(name string) error
	ServiceRequestSetHeader(name string, value string) error

	ClientGetCredential() (client.AuthenticatedCredential, error)
	ClientAuthenticate(consumer *entities.Consumer, credential *client.AuthenticatedCredential) error
	ClientLoadConsumer(consumerID string, byUsername bool) (entities.Consumer, error)
}

type KongPDKAdapter struct {
	PDK *pdk.PDK
}

func (kong *KongPDKAdapter) CtxSetShared(k string, value any) error {
	return kong.PDK.Ctx.SetShared(k, value)
}

func (kong *KongPDKAdapter) LogAlert(args ...any) error {
	return kong.PDK.Log.Alert(args...)
}

func (kong *KongPDKAdapter) LogCrit(args ...any) error {
	return kong.PDK.Log.Crit(args...)
}

func (kong *KongPDKAdapter) LogErr(args ...any) error {
	return kong.PDK.Log.Err(args...)
}

func (kong *KongPDKAdapter) LogWarn(args ...any) error {
	return kong.PDK.Log.Warn(args...)
}

func (kong *KongPDKAdapter) LogNotice(args ...any) error {
	return kong.PDK.Log.Notice(args...)
}

func (kong *KongPDKAdapter) LogInfo(args ...any) error {
	return kong.PDK.Log.Info(args...)
}

func (kong *KongPDKAdapter) LogDebug(args ...any) error {
	return kong.PDK.Log.Debug(args...)
}

func (kong *KongPDKAdapter) RequestGetPathWithQuery() (string, error) {
	return kong.PDK.Request.GetPathWithQuery()
}

func (kong *KongPDKAdapter) RequestGetHeader(k string) (string, error) {
	return kong.PDK.Request.GetHeader(k)
}

func (kong *KongPDKAdapter) RequestGetHeaders(maxHeaders int) (map[string][]string, error) {
	return kong.PDK.Request.GetHeaders(maxHeaders)
}

func (kong *KongPDKAdapter) RequestGetQueryArg(k string) (string, error) {
	return kong.PDK.Request.GetQueryArg(k)
}

func (kong *KongPDKAdapter) ResponseAddHeader(k string, v string) error {
	return kong.PDK.Response.AddHeader(k, v)
}

func (kong *KongPDKAdapter) ResponseExit(status int, body []byte, headers map[string][]string) {
	kong.PDK.Response.Exit(status, body, headers)
}

func (kong *KongPDKAdapter) ResponseExitStatus(status int) {
	kong.PDK.Response.ExitStatus(status)
}

func (kong *KongPDKAdapter) ResponseSetHeader(k string, v string) error {
	return kong.PDK.Response.SetHeader(k, v)
}

func (kong *KongPDKAdapter) ServiceRequestClearHeader(name string) error {
	return kong.PDK.ServiceRequest.ClearHeader(name)
}

func (kong *KongPDKAdapter) ServiceRequestSetHeader(name string, value string) error {
	return kong.PDK.ServiceRequest.SetHeader(name, value)
}

func (kong *KongPDKAdapter) ClientGetCredential() (client.AuthenticatedCredential, error) {
	return kong.PDK.Client.GetCredential()
}

func (kong *KongPDKAdapter) ClientAuthenticate(consumer *entities.Consumer, credential *client.AuthenticatedCredential) error {
	return kong.PDK.Client.Authenticate(consumer, credential)
}

func (kong *KongPDKAdapter) ClientLoadConsumer(consumerID string, byUsername bool) (entities.Consumer, error) {
	return kong.PDK.Client.LoadConsumer(consumerID, byUsername)
}
