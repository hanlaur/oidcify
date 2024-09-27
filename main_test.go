package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	//	"github.com/go-jose/go-jose/v4"
	//	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/oauth2-proxy/mockoidc"
	"golang.org/x/oauth2"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type httpBinResponse struct {
	Headers map[string]string `json:"headers"`
}

func ignoreLogCalls(mockKong *MockKong) {
	mockKong.On("LogDebug", mock.Anything).Maybe().Return(nil)
	mockKong.On("LogErr", mock.Anything).Maybe().Return(nil)
	mockKong.On("LogWarn", mock.Anything).Maybe().Return(nil)
	mockKong.On("LogInfo", mock.Anything).Maybe().Return(nil)
}

func TestOIDCPlugin(t *testing.T) { //nolint:funlen
	mockOidcServer, _ := mockoidc.Run()
	defer mockOidcServer.Shutdown() //nolint:errcheck
	cfg := mockOidcServer.Config()

	pluginConfig, ok := New().(*Config)
	assert.True(t, ok)

	pluginConfig.Issuer = cfg.Issuer
	pluginConfig.ClientID = cfg.ClientID
	pluginConfig.ClienSecret = cfg.ClientSecret
	pluginConfig.RedirectURI = "http://localhost/cb"
	pluginConfig.Scopes = []string{"openid", "profile", "email", "groups"}
	pluginConfig.HeadersFromClaims = map[string]string{
		"X-Oidc-Email":          "email",
		"X-Oidc-Email-Verified": "email_verified",
		"X-Oidc-Sub":            "sub",
		"X-Oidc-Pref-User":      "preferred_username",
		"X-Oidc-NotInToken":     "not_in_token",
	}

	t.Run("Kong API error", func(t *testing.T) {
		mock := NewMockKong(t)
		ignoreLogCalls(mock)

		mock.On("RequestGetHeaders", -1).Return(nil, errors.New("dummy error"))

		mock.EXPECT().ResponseExitStatus(http.StatusInternalServerError)

		pluginConfig.AccessWithInterface(mock)
	})

	// The number of expected cookies may need to be updated over time. Purpose of
	// this check is to ensure that multiple cookies actually end up being used.
	numOfGroupsToCookies := map[int]int{
		0:   1,
		1:   1,
		2:   1,
		3:   1,
		20:  1,
		100: 2,
		200: 3,
		500: 7,
		600: 9,
	}

	for numOfGroups, expectedNumOfCookies := range numOfGroupsToCookies {
		testName := fmt.Sprintf("Successful auth with %v groups", numOfGroups)
		t.Run(testName, func(t *testing.T) {
			groups := []string{}
			groupsAny := make([]any, 0)

			for groupIdx := range numOfGroups {
				groupName := fmt.Sprintf("groupname%v", groupIdx)
				groups = append(groups, groupName)
				groupsAny = append(groupsAny, groupName)
			}

			user := &mockoidc.MockUser{
				Subject:           "1234567890",
				Email:             "jane.doe@example.com",
				PreferredUsername: "mönkijä",
				Phone:             "555-987-6543",
				Address:           "123 Main Street",
				Groups:            groups,
				EmailVerified:     true,
			}

			mockOidcServer.QueueUser(user)

			mockKong := NewMockKong(t)

			ignoreLogCalls(mockKong)

			mockKong.On("RequestGetHeaders", -1).Return(map[string][]string{
				"cookie": {"OIDCSESSION0=invalid_value_that_cannot_be_decoded"},
			}, nil)
			mockKong.On("RequestGetPath").Return("/secretplace", nil)

			var locationHeaderValue string

			var oidcCookies []string

			mockKong.EXPECT().ResponseAddHeader("Set-Cookie", mock.AnythingOfType("string")).Return(nil).Run(
				func(_, v string) {
					oidcCookies = append(oidcCookies, v)
				})
			mockKong.EXPECT().ResponseSetHeader("Cache-Control", "no-store").Return(nil)
			mockKong.EXPECT().ResponseSetHeader("Location", mock.AnythingOfType("string")).Run(func(_, v string) {
				locationHeaderValue = v
			}).Return(nil)
			mockKong.EXPECT().ResponseExitStatus(http.StatusFound)

			pluginConfig.AccessWithInterface(mockKong)

			parsedURL, err := url.Parse(locationHeaderValue)
			require.NoError(t, err)

			queryParams := parsedURL.Query()

			codeChallengeMethod := queryParams.Get("code_challenge_method")
			redirectURI := queryParams.Get("redirect_uri")
			scope := queryParams.Get("scope")

			assert.Equal(t, "openid profile email groups", scope)
			assert.True(t, strings.HasPrefix(parsedURL.Host, "127.0.0.1:"))
			assert.Equal(t, mockoidc.AuthorizationEndpoint, parsedURL.Path)
			assert.Equal(t, "S256", codeChallengeMethod)
			assert.Equal(t, pluginConfig.RedirectURI, redirectURI)
			requestCookies := validateAndConvertOidcCookies(t, oidcCookies)
			assert.Len(t, requestCookies, 1)

			client := &http.Client{
				CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
			}

			authorizationResponse, err := client.Get(locationHeaderValue) //nolint:noctx
			require.NoError(t, err)

			defer authorizationResponse.Body.Close()

			cbLocationHeader := authorizationResponse.Header.Get("Location")
			assert.True(t, strings.HasPrefix(cbLocationHeader, pluginConfig.RedirectURI))

			parsedCBLoc, err := url.Parse(cbLocationHeader)
			require.NoError(t, err)

			mockKongCallback := NewMockKong(t)
			ignoreLogCalls(mockKongCallback)

			oidcCookies = nil

			mockKongCallback.EXPECT().RequestGetHeaders(-1).Return(map[string][]string{
				"cookie": requestCookies,
			}, nil)
			mockKongCallback.EXPECT().RequestGetPath().Return(parsedCBLoc.Path, nil)
			mockKongCallback.EXPECT().RequestGetQueryArg("code").Return(parsedCBLoc.Query().Get("code"), nil)
			mockKongCallback.EXPECT().RequestGetQueryArg("state").Return(parsedCBLoc.Query().Get("state"), nil)
			mockKongCallback.EXPECT().ResponseAddHeader("Set-Cookie", mock.AnythingOfType("string")).Return(nil).Run(func(_, v string) {
				oidcCookies = append(oidcCookies, v)
			})
			mockKongCallback.EXPECT().ResponseSetHeader("Location", "/secretplace").Return(nil)
			mockKongCallback.EXPECT().ResponseExitStatus(http.StatusFound)

			pluginConfig.AccessWithInterface(mockKongCallback)

			mockKongSecure := NewMockKong(t)
			ignoreLogCalls(mockKongSecure)

			mockKongSecure.EXPECT().RequestGetPath().Return("/secure", nil)

			requestCookies = validateAndConvertOidcCookies(t, oidcCookies)
			mockKongSecure.EXPECT().RequestGetHeaders(-1).Return(map[string][]string{
				"cookie": requestCookies,
			}, nil)
			mockKongSecure.EXPECT().CtxSetShared("authenticated_groups", groupsAny).Return(nil)
			mockKongSecure.EXPECT().ServiceRequestSetHeader("X-Oidc-Email", "jane.doe@example.com").Return(nil)
			mockKongSecure.EXPECT().ServiceRequestSetHeader("X-Oidc-Email-Verified", "true").Return(nil)
			mockKongSecure.EXPECT().ServiceRequestSetHeader("X-Oidc-Sub", "1234567890").Return(nil)
			mockKongSecure.EXPECT().ServiceRequestClearHeader("X-Oidc-NotInToken").Return(nil)
			mockKongSecure.EXPECT().ServiceRequestSetHeader("X-Oidc-Pref-User", "m%F6nkij%E4").Return(nil)

			pluginConfig.AccessWithInterface(mockKongSecure)

			mockKongLogout := NewMockKong(t)
			mockKongLogout.EXPECT().RequestGetPath().Return("/logout", nil)
			mockKongLogout.EXPECT().RequestGetHeaders(-1).Return(map[string][]string{
				"cookie": requestCookies,
			}, nil)

			deletedCookieCount := 0

			mockKongLogout.EXPECT().ResponseAddHeader("Set-Cookie", mock.AnythingOfType("string")).Run(func(_, v string) {
				assert.Regexp(t, "^OIDCSESSION[0-9]=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax$", v)
				deletedCookieCount++
			}).Return(nil)

			mockKongLogout.EXPECT().ResponseSetHeader("Cache-Control", "no-store").Return(nil)
			mockKongLogout.EXPECT().ResponseExit(http.StatusOK, mock.Anything, map[string][]string{"Content-Type": {"text/html"}})
			pluginConfig.AccessWithInterface(mockKongLogout)

			assert.Equal(t, len(requestCookies), deletedCookieCount)
			assert.Equal(t, expectedNumOfCookies, deletedCookieCount)
		})
	}
}

func validateAndConvertOidcCookies(t *testing.T, oidcCookies []string) []string {
	t.Helper()

	requestCookies := make([]string, 0, len(oidcCookies))

	for _, oidcCookie := range oidcCookies {
		assert.Regexp(t, "^OIDCSESSION[0-9]=.*; Path=/; HttpOnly; Secure; SameSite=Lax$", oidcCookie)
		requestCookie := strings.Split(oidcCookie, ";")[0]
		requestCookies = append(requestCookies, requestCookie)
	}

	return requestCookies
}

func TestBearerJWTOKAndExpired(t *testing.T) {
	mockOidcServer, _ := mockoidc.Run()
	defer mockOidcServer.Shutdown() //nolint:errcheck

	mockOidcServer.AccessTTL = time.Duration(10) * time.Second
	cfg := mockOidcServer.Config()

	pluginConfig, ok := New().(*Config)
	assert.True(t, ok)

	pluginConfig.Issuer = cfg.Issuer
	pluginConfig.ClientID = cfg.ClientID
	pluginConfig.ClienSecret = cfg.ClientSecret
	pluginConfig.RedirectURI = "http://localhost/cb"
	pluginConfig.Scopes = []string{"openid", "profile", "email", "groups"}
	pluginConfig.BearerJWTAllowedAuds = []string{cfg.ClientID}
	pluginConfig.CookieBlockKeyHex = "08ea7af807955a8219fba9efc1c1c9b62515ade6c48a936b6b136a802300b469"
	pluginConfig.CookieHashKeyHex = "ff74aab316f7070e0fb2288cb5fd456369d0f693927ec2b079b5f71702020df6"
	pluginConfig.RedirectUnauthenticated = false
	pluginConfig.HeadersFromClaims = map[string]string{
		"X-Oidc-Email": "email",
	}

	user := &mockoidc.MockUser{
		Subject:           "1234567890",
		Email:             "jane.doe@example.com",
		PreferredUsername: "mönkijä",
		Phone:             "555-987-6543",
		Address:           "123 Main Street",
		Groups:            []string{"readers", "writers", "unsafe\ngroup", "unsafe group äöå"},
		EmailVerified:     true,
	}
	mockOidcServer.QueueUser(user)

	provider, err := oidc.NewProvider(context.Background(), cfg.Issuer)
	require.NoError(t, err)

	oauth2Config := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  "http://localhost/cb",
		Endpoint:     provider.Endpoint(),
		Scopes:       pluginConfig.Scopes,
	}

	state := "state1234"
	pkceVerifier := "pkce1234"

	authCodeURL := oauth2Config.AuthCodeURL(state,
		oauth2.S256ChallengeOption(pkceVerifier))

	httpClient := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := httpClient.Get(authCodeURL) //nolint:noctx
	require.NoError(t, err)

	defer resp.Body.Close()

	cbLocationHeader := resp.Header.Get("Location")
	parsedCBLoc, err := url.Parse(cbLocationHeader)
	require.NoError(t, err)

	code := parsedCBLoc.Query().Get("code")

	token, err := oauth2Config.Exchange(context.Background(), code,
		oauth2.VerifierOption(pkceVerifier))
	require.NoError(t, err)

	rawIDToken, okToken := token.Extra("id_token").(string)
	if !okToken {
		t.Fatal("no id_token in token response")
	}

	mockKong := NewMockKong(t)

	ignoreLogCalls(mockKong)
	mockKong.EXPECT().RequestGetHeader("authorization").Return("Bearer "+rawIDToken, nil)
	mockKong.EXPECT().CtxSetShared("authenticated_groups", []any{"readers", "writers"}).Return(nil)
	mockKong.EXPECT().ServiceRequestSetHeader("X-Oidc-Email", "jane.doe@example.com").Return(nil)
	pluginConfig.AccessWithInterface(mockKong)

	// Wait for token to expire
	time.Sleep(time.Duration(11) * time.Second)

	mockKong = NewMockKong(t)

	ignoreLogCalls(mockKong)
	mockKong.EXPECT().RequestGetHeader("authorization").Return("Bearer "+rawIDToken, nil)
	mockKong.EXPECT().RequestGetHeaders(-1).Return(map[string][]string{}, nil)
	mockKong.EXPECT().RequestGetPath().Return("/api/getdata", nil)
	mockKong.EXPECT().ResponseSetHeader("Cache-Control", "no-store").Return(nil)
	mockKong.EXPECT().ResponseExitStatus(http.StatusUnauthorized)
	pluginConfig.AccessWithInterface(mockKong)
}

func TestRealKongRedirectAndACL(t *testing.T) {
	if os.Getenv("SKIP_EXT_TESTS") != "" {
		t.Skip("Skipping tests requiring external services")

		return
	}

	// route requests via squid for host names to work in redirects
	proxyURL, err := url.Parse("http://localhost:3128")
	if err != nil {
		t.Fatal(err)
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec
		},
	}

	cookieJar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}

	httpClient := &http.Client{
		Jar:       cookieJar,
		Transport: transport,
	}

	// OIDC cookie requires https. Client will be redirected to the Mock OIDC provider and back as HTTP client follows redirects
	resp, err := httpClient.Get("https://kong/headers") //nolint:noctx
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status code: %v", resp.StatusCode)
	}

	var httpBinResponse httpBinResponse

	err = json.NewDecoder(resp.Body).Decode(&httpBinResponse)
	if err != nil {
		t.Fatal(err)
	}

	for expectedHeader, expectedValue := range map[string]string{
		"X-Oidc-Email":            "user@mock.internal",
		"X-Oidc-Email-Verified":   "true",
		"X-Oidc-Sub":              "sub12345678",
		"X-Oidc-Dummy-Int":        "223344",
		"X-Authenticated-Groups":  "readers",
		"X-Credential-Identifier": "sub12345678",
		"X-Consumer-Id":           "ffe30af5-d167-519a-8bdc-2fa89a3aa280",
		"X-Consumer-Username":     "oidcuser",
	} {
		if httpBinResponse.Headers[expectedHeader] != expectedValue {
			t.Fatalf("unexpected %v: %v", expectedHeader, httpBinResponse.Headers[expectedHeader])
		}
	}

	// From now on, requests should not anymore be redirected to OIDC provider using the session cookie
	noRedirectClient := &http.Client{
		Jar:           cookieJar,
		Transport:     transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}

	resp, err = noRedirectClient.Get("https://kong/headers") //nolint:noctx
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status code: %v", resp.StatusCode)
	}

	// Should be blocked by ACL plugin
	resp, err = noRedirectClient.Get("https://kong/secret") //nolint:noctx
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unexpected status code: %v", resp.StatusCode)
	}
}

func TestRealKongSkipAlreadyAuth(t *testing.T) {
	if os.Getenv("SKIP_EXT_TESTS") != "" {
		t.Skip("Skipping tests requiring external services")

		return
	}

	// route requests via squid for host names to work in redirects
	proxyURL, err := url.Parse("http://localhost:3128")
	if err != nil {
		t.Fatal(err)
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec
		},
	}

	httpClient := &http.Client{
		Transport:     transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}

	req, err := http.NewRequest(http.MethodGet, "https://kong/headers", nil) //nolint:noctx
	if err != nil {
		t.Fatal(err)
	}

	req.SetBasicAuth("john", "basic")

	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status code: %v", resp.StatusCode)
	}

	var httpBinResponse httpBinResponse

	err = json.NewDecoder(resp.Body).Decode(&httpBinResponse)
	if err != nil {
		t.Fatal(err)
	}

	// For safety, validate that groups were sources from the basic auth plugin
	if h := httpBinResponse.Headers["X-Consumer-Groups"]; h != "basicusers" {
		t.Fatalf("unexpected groups: %v", h)
	}
}