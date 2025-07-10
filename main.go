package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Kong/go-pdk"

	"github.com/Kong/go-pdk/client"
	"github.com/Kong/go-pdk/server"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/securecookie"
	"github.com/jellydator/ttlcache/v3"
	"golang.org/x/oauth2"

	"github.com/go-playground/validator/v10"
)

type URIType int

const (
	_ URIType = iota
	URITypeRedirect
	URITypeLogout
	URITypeRegular
)

const (
	cookieKeyLenBytes           = 32
	oAuth2StateLenBytes         = 32
	oAuth2PKCELenBytes          = 32
	oidcNonceLenBytes           = 32
	maxCookieLenChars           = 4000
	maxNumCookies               = 10
	oidcProviderCacheTimeSecs   = 300
	httpClientTimeoutSecs       = 15
	maxAuthCodeFlowDurationSecs = 600
)

var version = "0.0.0" // goreleaser sets via ldflags

var (
	// The autoGen keys are used if user plugin configuration does not define keys.
	autoGenHashKey  = securecookie.GenerateRandomKey(cookieKeyLenBytes)
	autoGenBlockKey = securecookie.GenerateRandomKey(cookieKeyLenBytes)
	validate        = validator.New(validator.WithRequiredStructEnabled())
)

type OIDCProvider struct {
	Provider   *oidc.Provider
	HTTPClient *http.Client
}

// oidcProviderCache caches OIDC provider, avoiding repeated discovery and JWKS requests.
var oidcProviderCache *ttlcache.Cache[string, *OIDCProvider] = ttlcache.New[string, *OIDCProvider](
	ttlcache.WithTTL[string, *OIDCProvider](time.Second*oidcProviderCacheTimeSecs),
	ttlcache.WithDisableTouchOnHit[string, *OIDCProvider]())

// Config defines the plugin configuration that user can provide.
type Config struct {
	// OIDC
	Issuer       string   `json:"issuer"        validate:"required,http_url"`
	ClientID     string   `json:"client_id"     validate:"required"`
	ClientSecret string   `json:"client_secret" validate:"required"`
	RedirectURI  string   `json:"redirect_uri"  validate:"required,http_url"`
	GroupsClaim  string   `json:"groups_claim"`
	Scopes       []string `json:"scopes"        validate:"required"`
	UsePKCE      bool     `json:"use_pkce"`
	UseUserInfo  bool     `json:"use_userinfo"`
	CACertFiles  []string `json:"ca_cert_files"`

	// Static OIDC provider configuration to skip discovery
	StaticProviderConfig ProviderConfig `json:"static_provider_config"`

	// Bearer JWT Auth
	BearerJWTAllowedAuds []string `json:"bearer_jwt_allowed_auds"`
	BearerJWTAllowedAlgs []string `json:"bearer_jwt_allowed_algs" validate:"required,min=1"`

	// Session management
	CookieName             string `json:"cookie_name"              validate:"required"`
	CookieHashKeyHex       string `json:"cookie_hash_key_hex"      validate:"omitempty,hexadecimal,len=64"`
	CookieBlockKeyHex      string `json:"cookie_block_key_hex"     validate:"omitempty,hexadecimal,len=64"`
	SessionLifetimeSeconds int    `json:"session_lifetime_seconds" validate:"gte=0"`

	// Behavior
	RedirectUnauthenticated bool              `json:"redirect_unauthenticated"`
	LogoutPath              string            `json:"logout_path"              validate:"required"`
	PostLogoutRedirectURI   string            `json:"post_logout_redirect_uri" validate:"omitempty,http_url"`
	HeadersFromClaims       map[string]string `json:"headers_from_claims"`
	IDTokenClaimsHeader     string            `json:"id_token_claims_header"`
	UserInfoClaimsHeader    string            `json:"userinfo_claims_header"`
	SkipAlreadyAuth         bool              `json:"skip_already_auth"`
	ConsumerName            string            `json:"consumer_name"            validate:"required"`
}

type ProviderConfig struct {
	AuthURL     string   `json:"authorization_endpoint"                validate:"required_with=TokenURL,omitempty,http_url"`
	TokenURL    string   `json:"token_endpoint"                        validate:"required_with=AuthURL,omitempty,http_url"`
	UserInfoURL string   `json:"userinfo_endpoint"                     validate:"omitempty,http_url"`
	JWKSURL     string   `json:"jwks_uri"                              validate:"required_with=AuthURL TokenURL UserInfoURL Algorithms,omitempty,http_url"` //nolint:lll
	Algorithms  []string `json:"id_token_signing_alg_values_supported" validate:"required_with=JWKSURL,omitempty,min=1"`
}

// AuthState holds the state of an ongoing OIDC Authorization Code flow (from redirect to callback).
type AuthState struct {
	ValidUntil       time.Time
	State            string
	PKCECodeVerifier string
	Nonce            string
	OriginalURI      string
}

// SessionData is stored in the encrypted cookie.
type SessionData struct {
	AuthenticationComplete bool
	OngoingAuth            AuthState
	RawIDToken             string
	UserInfoClaims         map[string]any
}

// New returns a new instance of the plugin configuration.
func New() interface{} {
	defaultConfig := Config{
		GroupsClaim:             "groups",
		Scopes:                  []string{"openid"},
		UsePKCE:                 true,
		CookieName:              "OIDCSESSION",
		RedirectUnauthenticated: true,
		LogoutPath:              "/logout",
		BearerJWTAllowedAlgs:    []string{"RS256"},
	}

	return &defaultConfig
}

// Get instance of SecureCookie that can be used to encrypt/decrypt session data to cookie.
func getSecureCookie(hashKeyHex, blockKeyHex string) (*securecookie.SecureCookie, error) {
	hashKey := autoGenHashKey
	blockKey := autoGenBlockKey

	if len(hashKeyHex) > 0 {
		hashKeyDecoded, err := hex.DecodeString(hashKeyHex)
		if err != nil {
			return nil, fmt.Errorf("error decoding hex hash key: %w", err)
		}

		hashKey = hashKeyDecoded
	}

	if len(blockKeyHex) > 0 {
		blockKeyDecoded, err := hex.DecodeString(blockKeyHex)
		if err != nil {
			return nil, fmt.Errorf("error decoding hex block key: %w", err)
		}

		blockKey = blockKeyDecoded
	}

	if len(hashKey) != cookieKeyLenBytes || len(blockKey) != cookieKeyLenBytes {
		return nil, fmt.Errorf("hash and block key must be %v bytes (%v hex)", cookieKeyLenBytes, 2*cookieKeyLenBytes) //nolint:mnd
	}

	sCookie := securecookie.New(hashKey, blockKey).MaxLength(maxNumCookies * maxCookieLenChars)
	sCookie.SetSerializer(securecookie.JSONEncoder{}) // default Gob encoder does not handle map[string]any

	return sCookie, nil
}

// Get request cookies from Kong and translate them to go http.Cookie objects.
func getRequestCookies(kong Kong) ([]*http.Cookie, error) {
	headers, err := kong.RequestGetHeaders(-1)
	if err != nil {
		return nil, fmt.Errorf("unable to get request headers: %w", err)
	}

	cookieHeaders, ok := headers["cookie"]

	if !ok {
		return []*http.Cookie{}, nil
	}

	// Use http.Request as helper for parsing cookies. Header name needs to be uppercase.
	request := http.Request{Header: http.Header{"Cookie": cookieHeaders}}

	return request.Cookies(), nil
}

// getSesssion loads session data from encrypted cookie or returns empty session if there is no session
// or if the session cannot be decoded with currently configured keys.
func getSession(
	kong Kong,
	sCookie *securecookie.SecureCookie,
	requestCookies []*http.Cookie,
	sessionCookieName string,
) *SessionData {
	var sessionCookie string

	for i := range maxNumCookies {
		cookieName := sessionCookieName + strconv.Itoa(i)
		for _, cookie := range requestCookies {
			if cookie.Name == cookieName {
				sessionCookie += cookie.Value

				break
			}
		}
	}

	if sessionCookie != "" {
		var sessionData SessionData

		err := sCookie.Decode(sessionCookieName, sessionCookie, &sessionData)
		if err != nil {
			kong.LogWarn(fmt.Sprintf("Unable to restore old session, session decode failed: %v", err))
		} else {
			return &sessionData
		}
	}

	return &SessionData{}
}

// setCookies sets cookie headers in the response, taking care of splitting the data into multiple cookies
// and deleting old cookies as necessary, as number of cookies may change compared to previous state.
func setCookies(kong Kong, encodedStr string, sessionCookieName string, requestCookies []*http.Cookie) error {
	if cookieLen := len(encodedStr); cookieLen > maxNumCookies*maxCookieLenChars {
		return fmt.Errorf("cookie length %v would exceed %v*%v", cookieLen, maxNumCookies, maxCookieLenChars)
	}

	for cookieIdx := range maxNumCookies {
		cookieName := sessionCookieName + strconv.Itoa(cookieIdx)

		var cookieToSet *http.Cookie

		if len(encodedStr) > 0 {
			bytesToTake := min(maxCookieLenChars, len(encodedStr))
			component := encodedStr[0:bytesToTake]
			encodedStr = encodedStr[bytesToTake:]

			cookieToSet = &http.Cookie{
				Name:     cookieName,
				Value:    component,
				Secure:   true,
				HttpOnly: true,
				Path:     "/",
				SameSite: http.SameSiteLaxMode,
			}
		} else {
			for _, requestCookie := range requestCookies {
				if requestCookie.Name == cookieName {
					cookieToSet = &http.Cookie{
						Name:     cookieName,
						Value:    "",
						Secure:   true,
						HttpOnly: true,
						Path:     "/",
						SameSite: http.SameSiteLaxMode,
						MaxAge:   -1,
					}
				}
			}
		}

		if cookieToSet == nil {
			continue
		}

		cookieStr := cookieToSet.String()
		if cookieStr == "" {
			return fmt.Errorf("unable to create cookie %v", cookieToSet.Name)
		}

		if err := kong.ResponseAddHeader("Set-Cookie", cookieStr); err != nil {
			return fmt.Errorf("unable to add Set-Cookie header: %w", err)
		}
	}

	return nil
}

// setSession stores session data into encrypted cookie and sets them in the response.
func setSession(
	kong Kong,
	sCookie *securecookie.SecureCookie,
	requestCookies []*http.Cookie,
	sessionCookieName string,
	session *SessionData,
) error {
	encodedStr, err := sCookie.Encode(sessionCookieName, session)
	if err != nil {
		return fmt.Errorf("session cookie encode failed: %w", err)
	}

	return setCookies(kong, encodedStr, sessionCookieName, requestCookies)
}

// deleteSession clears any existing session data cookies.
func deleteSession(kong Kong, requestCookies []*http.Cookie, sessionCookieName string) error {
	return setCookies(kong, "", sessionCookieName, requestCookies)
}

func createHTTPClient(caCertFiles []string) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone() //nolint: forcetypeassert
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}

	if len(caCertFiles) > 0 {
		certPool := x509.NewCertPool()

		for _, caCertFile := range caCertFiles {
			caCert, err := os.ReadFile(caCertFile)
			if err != nil {
				return nil, fmt.Errorf("failed to read CA cert file: %w", err)
			}

			if !certPool.AppendCertsFromPEM(caCert) {
				return nil, fmt.Errorf("could not load PEM certs from %v", caCertFile)
			}

			transport.TLSClientConfig.RootCAs = certPool
		}
	}

	client := &http.Client{Transport: transport, Timeout: httpClientTimeoutSecs * time.Second}

	return client, nil
}

// Return new background context that carries a HTTP client that OIDC/oauth library will use
// for HTTP requests towards the OIDC provider.
func newContextWithOidcHTTPClient(httpClient *http.Client) context.Context {
	return oidc.ClientContext(context.Background(), httpClient)
}

// Return OIDC provider instance for the given issuer, either from cache or by creating a new one.
func getOIDCProvider(kong Kong, issuer string, manualProviderConfig *ProviderConfig, caCertFiles []string) (*OIDCProvider, error) {
	cacheKey := fmt.Sprintf("%v/%#v/%v", issuer, manualProviderConfig, caCertFiles)

	item := oidcProviderCache.Get(cacheKey)

	if item == nil { //nolint:nestif
		httpClient, err := createHTTPClient(caCertFiles)
		if err != nil {
			return nil, fmt.Errorf("failed to create HTTP client: %w", err)
		}

		var provider *oidc.Provider

		if manualProviderConfig.JWKSURL != "" {
			providerConfig := oidc.ProviderConfig{
				IssuerURL:   issuer,
				AuthURL:     manualProviderConfig.AuthURL,
				TokenURL:    manualProviderConfig.TokenURL,
				UserInfoURL: manualProviderConfig.UserInfoURL,
				JWKSURL:     manualProviderConfig.JWKSURL,
				Algorithms:  manualProviderConfig.Algorithms,
			}
			provider = providerConfig.NewProvider(newContextWithOidcHTTPClient(httpClient))
		} else {
			var err error

			provider, err = oidc.NewProvider(newContextWithOidcHTTPClient(httpClient), issuer)
			if err != nil {
				return nil, fmt.Errorf("OIDC provider initialization failed: %w", err)
			}
		}

		kong.LogInfo(fmt.Sprintf("OIDC provider endpoints: %+v", provider.Endpoint()))

		oidcProvider := &OIDCProvider{Provider: provider, HTTPClient: httpClient}

		item = oidcProviderCache.Set(cacheKey, oidcProvider, ttlcache.DefaultTTL)
	}

	return item.Value(), nil
}

func getURIType(conf *Config, requestPathWithQuery string) (URIType, error) {
	parsedRedirectURI, err := url.Parse(conf.RedirectURI)
	if err != nil {
		var empty URIType

		return empty, fmt.Errorf("unable to parse configured redirect URL %v: %w", conf.RedirectURI, err)
	}

	parsedRequestPath, err := url.Parse(requestPathWithQuery)
	if err != nil {
		var empty URIType

		return empty, fmt.Errorf("unable to parse request path %v: %w", requestPathWithQuery, err)
	}

	switch parsedRequestPath.Path {
	case parsedRedirectURI.Path:
		return URITypeRedirect, nil
	case conf.LogoutPath:
		return URITypeLogout, nil
	default:
		return URITypeRegular, nil
	}
}

// Return cryptographically strong random hex string.
func randomHexString(numBytes int) (string, error) {
	bytes := make([]byte, numBytes)

	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("error generating random hex string: %w", err)
	}

	return hex.EncodeToString(bytes), nil
}

// Adapts input string to be safe for use as a header value by using URL-encoding
// for characters other than VCHAR (0x21-0x7E), SP, HTAB.
func safeHeaderValue(input string) string {
	var result strings.Builder

	for _, ch := range input {
		if (ch >= 0x21 && ch <= 0x7E) || ch == ' ' || ch == '\t' {
			result.WriteRune(ch)
		} else {
			result.WriteString(fmt.Sprintf("%%%02X", ch))
		}
	}

	return result.String()
}

func getOauth2Config(conf *Config, provider *oidc.Provider) oauth2.Config {
	oauth2Config := oauth2.Config{
		ClientID:     conf.ClientID,
		ClientSecret: conf.ClientSecret,
		RedirectURL:  conf.RedirectURI,
		Endpoint:     provider.Endpoint(),
		Scopes:       conf.Scopes,
	}

	return oauth2Config
}

func validateConfig(conf *Config) error {
	return validate.Struct(conf) //nolint:wrapcheck
}

// Set the service data headers based on OIDC claims, according to user configured mappings.
func setServiceDataHeadersFromClaims(conf Config, idTokenClaims map[string]any, userInfoClaims map[string]any, kong Kong) error {
	for header, claim := range conf.HeadersFromClaims {
		var headerValue string

		var headerValueSet bool

		claimValue, ok := idTokenClaims[claim]
		if !ok && userInfoClaims != nil {
			claimValue, ok = userInfoClaims[claim]
		}

		if ok {
			switch val := claimValue.(type) {
			case string:
				headerValue = safeHeaderValue(val)
				headerValueSet = true
			case bool:
				headerValue = strconv.FormatBool(val)
				headerValueSet = true
			case float64:
				headerValue = fmt.Sprintf("%v", val)
				headerValueSet = true
			default:
				kong.LogWarn(fmt.Sprintf("Claim %v is a %T value. Conversion not supported.", claim, claimValue))
			}
		}

		if headerValueSet {
			if err := kong.ServiceRequestSetHeader(header, headerValue); err != nil {
				return fmt.Errorf("failed to set header %v: %w", header, err)
			}
		} else {
			if err := kong.ServiceRequestClearHeader(header); err != nil {
				return fmt.Errorf("failed to clear header %v: %w", header, err)
			}
		}
	}

	for claimsHeader, claims := range map[string]map[string]any{
		conf.IDTokenClaimsHeader:  idTokenClaims,
		conf.UserInfoClaimsHeader: userInfoClaims,
	} {
		if claimsHeader == "" {
			continue
		}

		claimsJSON, err := json.Marshal(claims)
		if err != nil {
			return fmt.Errorf("unable to marshal claims for header %v. Claims %#v: %w", claimsHeader, claims, err)
		}

		claimsJSONBase64 := base64.StdEncoding.EncodeToString(claimsJSON)

		if err := kong.ServiceRequestSetHeader(claimsHeader, claimsJSONBase64); err != nil {
			return fmt.Errorf("failed to set header %v: %w", claimsHeader, err)
		}
	}

	return nil
}

// Append group string to groups slice if it is safe for use in HTTP headers and Kong X-Authorized-Groups header.
func appendIfSafeGroupStr(kong Kong, groups []any, groupStr string) []any {
	// Following pattern may need to be extended to allow more characters.
	// Target is to have characters that are both safe for use in HTTP headers, and
	// safe for use in Kong X-Authorized-Groups header that the ACL plugin will construct.
	// Assumption is that kong separates the groups by ", " (comma and space). Below allows
	// comma, but not space.
	pattern := `^[A-Za-z0-9.,-/!#$%&+:;<=>@_]+$`

	match, err := regexp.MatchString(pattern, groupStr)
	if err == nil && match {
		groups = append(groups, groupStr)
	} else {
		kong.LogWarn(fmt.Sprintf("Ignoring group name not compliant with pattern %v: %v", pattern, groupStr))
	}

	return groups
}

// Sets groups in Kong context shared variable based on ID token claim so that Kong ACL plugin can use them.
func setServiceDataGroups(idTokenClaims map[string]any, conf Config, kong Kong) error {
	authenticatedGroups := make([]any, 0)

	groupsValue, ok := idTokenClaims[conf.GroupsClaim]

	if ok {
		switch val := groupsValue.(type) {
		case []interface{}:
			for _, group := range val {
				if groupStr, ok := group.(string); ok {
					authenticatedGroups = appendIfSafeGroupStr(kong, authenticatedGroups, groupStr)
				} else {
					kong.LogWarn(fmt.Sprintf("Skipping group: Unable to convert group to string: %v", group))
				}
			}
		case string:
			authenticatedGroups = appendIfSafeGroupStr(kong, authenticatedGroups, val)
		default:
			kong.LogWarn(fmt.Sprintf("Unable to process groups claim value: %v", groupsValue))
		}
	} else {
		kong.LogDebug("No groups claim within ID token claims")
	}

	if err := kong.CtxSetShared("authenticated_groups", authenticatedGroups); err != nil {
		return fmt.Errorf("unable to set authenticated groups: %w", err)
	}

	return nil
}

// Sets Kong consumer and credential for the request.
func setServiceDataAuth(idTokenClaims map[string]any, conf Config, kong Kong) error {
	consumer, err := kong.ClientLoadConsumer(conf.ConsumerName, true)
	if err != nil {
		return fmt.Errorf("unable to load consumer %v: %w", conf.ConsumerName, err)
	}

	subClaim, okCredID := idTokenClaims["sub"]
	if !okCredID {
		return errors.New("ID token does not contain sub claim")
	}

	credentialIdentifier, okSubClaim := subClaim.(string)
	if !okSubClaim {
		return errors.New("sub claim is not a string")
	}

	credential := client.AuthenticatedCredential{
		Id:         credentialIdentifier,
		ConsumerId: consumer.Id,
	}

	err = kong.ClientAuthenticate(&consumer, &credential)
	if err != nil {
		return fmt.Errorf("unable to set kong authentication as consumer=%v: %w", consumer, err)
	}

	headerMap := map[string]string{
		"X-Consumer-Id":           consumer.Id,
		"X-Consumer-Custom-Id":    consumer.CustomId,
		"X-Consumer-Username":     consumer.Username,
		"X-Anonymous-Consumer":    "",
		"X-Credential-Identifier": credentialIdentifier,
	}

	for header, val := range headerMap {
		if val != "" {
			err = kong.ServiceRequestSetHeader(header, val)
		} else {
			err = kong.ServiceRequestClearHeader(header)
		}

		if err != nil {
			return fmt.Errorf("unable to set or clear header %v to %v: %w", header, val, err)
		}
	}

	return nil
}

// Sets service data (Kong authentication, groups, mapped headers) based on ID token claims and user info claims.
func setServiceData(idTokenClaims, userInfoClaims map[string]any, conf Config, kong Kong) error {
	if err := setServiceDataAuth(idTokenClaims, conf, kong); err != nil {
		return err
	}

	if err := setServiceDataGroups(idTokenClaims, conf, kong); err != nil {
		return err
	}

	if err := setServiceDataHeadersFromClaims(conf, idTokenClaims, userInfoClaims, kong); err != nil {
		return err
	}

	return nil
}

// Performs further ID token validations that are not included in OIDC library Verify function.
func verifyIDTokenCommon(idToken *oidc.IDToken) error {
	if idToken.Subject == "" {
		return errors.New("token does not contain sub claim")
	}

	// Currently limit implementation to single-audience tokens
	if len(idToken.Audience) != 1 {
		return errors.New("token does not contain exactly one audience")
	}

	if idToken.IssuedAt.IsZero() {
		return errors.New("token does not contain iat claim")
	}

	return nil
}

// authSessionVerifyIDToken verifies the ID token, session expiry and returns the ID token claim if successful.
func authSessionVerifyIDToken(conf Config, session *SessionData, oidcProvider *OIDCProvider) (map[string]any, error) {
	// If session lifetime is configured, skip expiry check by the verifier as this functon will check it separately.
	skipVerifierExpiryCheck := conf.SessionLifetimeSeconds > 0

	verifier := oidcProvider.Provider.Verifier(&oidc.Config{ClientID: conf.ClientID, SkipExpiryCheck: skipVerifierExpiryCheck})

	idToken, err := verifier.Verify(newContextWithOidcHTTPClient(oidcProvider.HTTPClient), session.RawIDToken)
	if err != nil {
		return nil, fmt.Errorf("ID token verification failed: %w", err)
	}

	if skipVerifierExpiryCheck {
		sessionExpiryTime := idToken.IssuedAt.Add(time.Second * time.Duration(conf.SessionLifetimeSeconds))

		if time.Now().After(sessionExpiryTime) {
			return nil, errors.New("session expired")
		}
	}

	var idTokenClaims map[string]any
	if err := idToken.Claims(&idTokenClaims); err != nil {
		return nil, fmt.Errorf("extracting claims from ID token failed: %w", err)
	}

	if err := verifyIDTokenCommon(idToken); err != nil {
		return nil, err
	}

	return idTokenClaims, nil
}

// authSessionURILogout implement OIDC Authorization code flow logic for handling requests to the logout URI.
func authSessionURILogout(
	kong Kong,
	conf Config,
	requestCookies []*http.Cookie,
) error {
	err := deleteSession(kong, requestCookies, conf.CookieName)
	if err != nil {
		return fmt.Errorf("unable to delete session  %w", err)
	}

	err = kong.ResponseSetHeader("Cache-Control", "no-store")
	if err != nil {
		return fmt.Errorf("failed to set Cache-Control header: %w", err)
	}

	if conf.PostLogoutRedirectURI != "" {
		err = kong.ResponseSetHeader("Location", conf.PostLogoutRedirectURI)
		if err != nil {
			return fmt.Errorf("failed to set Location header: %w", err)
		}

		kong.ResponseExitStatus(http.StatusFound)
	} else {
		kong.ResponseExit(http.StatusOK, []byte("<html><body>Logged out</body></html>"),
			map[string][]string{"Content-Type": {"text/html"}})
	}

	return nil
}

// authSessionURIRedirect implement OIDC Authorization code flow logic for handling requests to the redirect URI.
func authSessionURIRedirect(
	kong Kong,
	conf Config,
	oidcProvider *OIDCProvider,
	sCookie *securecookie.SecureCookie,
	requestCookies []*http.Cookie,
) error {
	var err error

	session := getSession(kong, sCookie, requestCookies, conf.CookieName)

	oauth2Config := getOauth2Config(&conf, oidcProvider.Provider)

	if time.Now().After(session.OngoingAuth.ValidUntil) {
		kong.LogErr("Received callback when authentication not in progress or auth took too long")

		err = kong.ResponseSetHeader("Cache-Control", "no-store")
		if err != nil {
			return fmt.Errorf("failed to set Cache-Control header: %w", err)
		}

		kong.ResponseExitStatus(http.StatusBadRequest)

		return nil
	}

	code, errCode := kong.RequestGetQueryArg("code")
	state, errState := kong.RequestGetQueryArg("state")

	if errCode != nil || errState != nil {
		return fmt.Errorf("unable to retrieve code or state from callback URI: code err %w, state err %w", errCode, errState)
	}

	if len(state) == 0 || len(code) == 0 {
		kong.LogErr("Callback does not include proper code or state query argument")

		err = kong.ResponseSetHeader("Cache-Control", "no-store")
		if err != nil {
			return fmt.Errorf("failed to set Cache-Control header: %w", err)
		}

		kong.ResponseExitStatus(http.StatusBadRequest)

		return nil
	}

	if state != session.OngoingAuth.State {
		kong.LogErr("State mismatch between request and callback. Not accepting callback")

		err = kong.ResponseSetHeader("Cache-Control", "no-store")
		if err != nil {
			return fmt.Errorf("failed to set Cache-Control header: %w", err)
		}

		kong.ResponseExitStatus(http.StatusBadRequest)

		return nil
	}

	var opts []oauth2.AuthCodeOption

	if conf.UsePKCE {
		opts = append(opts, oauth2.VerifierOption(session.OngoingAuth.PKCECodeVerifier))
	}

	oauth2token, err := oauth2Config.Exchange(newContextWithOidcHTTPClient(oidcProvider.HTTPClient), code, opts...)
	if err != nil {
		return fmt.Errorf("authorization code to token exchange failed: %w", err)
	}

	rawIDToken, ok := oauth2token.Extra("id_token").(string)
	if !ok {
		return errors.New("unable to retrieve ID token from token endpoint response")
	}

	session.RawIDToken = rawIDToken

	idTokenClaims, err := authSessionVerifyIDToken(conf, session, oidcProvider)
	if err != nil {
		return fmt.Errorf("session validation failed when processing callback: %w", err)
	}

	if session.OngoingAuth.Nonce != idTokenClaims["nonce"] {
		return errors.New("nonce mismatch between request and ID token")
	}

	if conf.UseUserInfo {
		oAuth2TokenSource := oauth2.StaticTokenSource(oauth2token)

		userInfo, err := oidcProvider.Provider.UserInfo(newContextWithOidcHTTPClient(oidcProvider.HTTPClient), oAuth2TokenSource)
		if err != nil {
			return fmt.Errorf("retrieving userinfo failed: %w", err)
		}

		if err := userInfo.Claims(&session.UserInfoClaims); err != nil {
			return fmt.Errorf("extracting claims from userinfo failed: %w", err)
		}
	}

	originalURI := session.OngoingAuth.OriginalURI

	session.OngoingAuth = AuthState{}

	session.AuthenticationComplete = true

	kong.LogInfo(fmt.Sprintf("Session set-up done: ID Token Claims=%#v, UserInfo Claims=%#v", idTokenClaims, session.UserInfoClaims))

	err = setSession(kong, sCookie, requestCookies, conf.CookieName, session)
	if err != nil {
		return fmt.Errorf("unable to set session  %w", err)
	}

	err = kong.ResponseSetHeader("Cache-Control", "no-store")
	if err != nil {
		return fmt.Errorf("failed to set Cache-Control header: %w", err)
	}

	err = kong.ResponseSetHeader("Location", originalURI)
	if err != nil {
		return fmt.Errorf("failed to set Location header: %w", err)
	}

	kong.ResponseExitStatus(http.StatusFound)

	return nil
}

// authSessionURIRegular implement OIDC Authorization code flow logic in case of regular URIs.
// Requests are either allowed to pass through, redirected to the OIDC provider for authentication, or
// denied.
func authSessionURIRegular(
	kong Kong,
	conf Config,
	sCookie *securecookie.SecureCookie,
	requestCookies []*http.Cookie,
	requestPathWithQuery string,
	oidcProvider *OIDCProvider,
) error {
	var err error

	session := getSession(kong, sCookie, requestCookies, conf.CookieName)

	if session.AuthenticationComplete {
		// ID token was validated already when handling the callback, and the session data is stored in
		// encrypted cookie, so except for expiry check, revalidation may be redundant. However
		// revalidation can reduce impact should the cookie encryption be compromised.
		idTokenClaims, err := authSessionVerifyIDToken(conf, session, oidcProvider)

		if err == nil {
			err = setServiceData(idTokenClaims, session.UserInfoClaims, conf, kong)
			if err != nil {
				return fmt.Errorf("error setting service data: %w", err)
			}

			// Session valid

			return nil
		}

		kong.LogDebug(fmt.Sprintf("Previously completed authentication not valid: %v", err))
	}

	// New session or old session not anymore valid

	if !conf.RedirectUnauthenticated {
		err = kong.ResponseSetHeader("Cache-Control", "no-store")
		if err != nil {
			return fmt.Errorf("failed to set Cache-Control header: %w", err)
		}

		kong.ResponseExitStatus(http.StatusUnauthorized)

		return nil
	}

	session = &SessionData{}

	state, errState := randomHexString(oAuth2StateLenBytes)
	pkceVerifier, errPKCE := randomHexString(oAuth2PKCELenBytes)
	nonce, errNonce := randomHexString(oidcNonceLenBytes)

	if errState != nil || errPKCE != nil || errNonce != nil {
		return fmt.Errorf("unable to generate secure state for PKCE %w, %w", errState, errPKCE)
	}

	session.OngoingAuth = AuthState{
		State:            state,
		PKCECodeVerifier: pkceVerifier,
		Nonce:            nonce,
		OriginalURI:      requestPathWithQuery,
		ValidUntil:       time.Now().Add(time.Second * maxAuthCodeFlowDurationSecs),
	}

	oauth2Config := getOauth2Config(&conf, oidcProvider.Provider)

	var opts []oauth2.AuthCodeOption

	opts = append(opts, oauth2.SetAuthURLParam("nonce", nonce))

	if conf.UsePKCE {
		opts = append(opts, oauth2.S256ChallengeOption(pkceVerifier))
	}

	authCodeURL := oauth2Config.AuthCodeURL(session.OngoingAuth.State, opts...)

	kong.LogDebug(fmt.Sprintf("Redirecting to %v", authCodeURL))

	err = setSession(kong, sCookie, requestCookies, conf.CookieName, session)
	if err != nil {
		return fmt.Errorf("unable to set session  %w", err)
	}

	err = kong.ResponseSetHeader("Cache-Control", "no-store")
	if err != nil {
		return fmt.Errorf("failed to set Cache-Control header: %w", err)
	}

	err = kong.ResponseSetHeader("Location", authCodeURL)
	if err != nil {
		return fmt.Errorf("failed to set Location header: %w", err)
	}

	kong.ResponseExitStatus(http.StatusFound)

	return nil
}

// authSession implements session-based authentication processing using the OIDC Authorization Code flow.
// Returns nil if request was successfully handled, error if not. Successful handling of request does not
// mean that the user is authenticated.
func authSession(kong Kong, conf Config, provider *OIDCProvider) error {
	sCookie, err := getSecureCookie(conf.CookieHashKeyHex, conf.CookieBlockKeyHex)
	if err != nil {
		return fmt.Errorf("unable to initialize secure cookie interface: %w", err)
	}

	requestCookies, err := getRequestCookies(kong)
	if err != nil {
		return fmt.Errorf("unable to parse request cookies: %w", err)
	}

	requestPathWithQuery, err := kong.RequestGetPathWithQuery()
	if err != nil {
		return fmt.Errorf("unable to get request path: %w", err)
	}

	uriType, err := getURIType(&conf, requestPathWithQuery)
	if err != nil {
		return fmt.Errorf("unable to determine URI type: %w", err)
	}

	switch uriType {
	case URITypeRegular:
		return authSessionURIRegular(kong, conf, sCookie, requestCookies, requestPathWithQuery, provider)

	case URITypeRedirect:
		return authSessionURIRedirect(kong, conf, provider, sCookie, requestCookies)

	case URITypeLogout:
		return authSessionURILogout(kong, conf, requestCookies)

	default:
		return fmt.Errorf("internal error: Unhandled uriType %v", uriType)
	}
}

// authBearerToken implements Bearer JWT token authentication processing
// Returns true if authentication was successfully completed, false if not.
func authBearerToken(kong Kong, conf Config, oidcProvider *OIDCProvider) (bool, error) {
	if len(conf.BearerJWTAllowedAuds) == 0 {
		return false, nil
	}

	authHeader, err := kong.RequestGetHeader("authorization")
	if err != nil {
		return false, fmt.Errorf("unable to check authorization header: %w", err)
	}

	authHeaderParts := strings.SplitN(authHeader, " ", 2) //nolint:mnd
	if len(authHeaderParts) != 2 {                        //nolint:mnd
		return false, nil
	}

	authScheme := authHeaderParts[0]
	credentials := strings.Trim(authHeaderParts[1], " ")

	if !(strings.ToLower(authScheme) == "bearer" && len(credentials) > 0) { //nolint:staticcheck
		return false, nil
	}

	verifier := oidcProvider.Provider.Verifier(&oidc.Config{SkipClientIDCheck: true, SupportedSigningAlgs: conf.BearerJWTAllowedAlgs})

	idToken, err := verifier.Verify(newContextWithOidcHTTPClient(oidcProvider.HTTPClient), credentials)
	if err != nil {
		kong.LogWarn(fmt.Sprintf("Bearer JWT token verification failed: %v", err))

		return false, nil
	}

	if err := verifyIDTokenCommon(idToken); err != nil {
		kong.LogWarn(fmt.Sprintf("Bearer JWT token verification failed: %v", err))

		return false, nil
	}

	foundAllowedAud := false

	for _, allowedAud := range conf.BearerJWTAllowedAuds {
		if slices.Contains(idToken.Audience, allowedAud) {
			foundAllowedAud = true
		}
	}

	if !foundAllowedAud {
		kong.LogWarn("Bearer JWT token did not contain any of the allowed audiences")

		return false, nil
	}

	var idTokenClaims map[string]any
	if err := idToken.Claims(&idTokenClaims); err != nil {
		return false, fmt.Errorf("extracting claims from token failed: %w", err)
	}

	err = setServiceData(idTokenClaims, nil, conf, kong)
	if err != nil {
		return false, fmt.Errorf("error setting service data: %w", err)
	}

	return true, nil
}

// AccessWithInterface is the plugin entry point for every HTTP request (in "Access" phase).
func (conf Config) AccessWithInterface(kong Kong) {
	if err := validateConfig(&conf); err != nil {
		kong.LogCrit(fmt.Sprintf("Config validation failed: %v", err))
		kong.ResponseExitStatus(http.StatusInternalServerError)

		return
	}

	if conf.SkipAlreadyAuth {
		authCred, err := kong.ClientGetCredential()
		if err != nil {
			kong.LogErr(fmt.Sprintf("Error getting credential: %v", err))
			kong.ResponseExitStatus(http.StatusInternalServerError)

			return
		}

		if authCred.Id != "" {
			kong.LogDebug("Skipping already authenticated request")

			return
		}
	}

	provider, err := getOIDCProvider(kong, conf.Issuer, &conf.StaticProviderConfig, conf.CACertFiles)
	if err != nil {
		kong.LogCrit(fmt.Sprintf("Unable to initialize OIDC provider: %v", err))
		kong.ResponseExitStatus(http.StatusInternalServerError)

		return
	}

	authComplete, err := authBearerToken(kong, conf, provider)
	if err != nil {
		kong.LogErr(fmt.Sprintf("Bearer JWT Auth failed: %v", err))
		kong.ResponseExitStatus(http.StatusInternalServerError)

		return
	}

	if authComplete {
		return
	}

	err = authSession(kong, conf, provider)
	if err != nil {
		kong.LogErr(fmt.Sprintf("Session-based Auth failed: %v", err))
		kong.ResponseExitStatus(http.StatusInternalServerError)

		return
	}
}

// Access is the plugin entry point called by Kong plugin server for every HTTP request (in "Access" phase).
func (conf Config) Access(kong *pdk.PDK) {
	adapter := &KongPDKAdapter{PDK: kong}
	conf.AccessWithInterface(adapter)
}

func main() {
	go oidcProviderCache.Start()
	defer oidcProviderCache.Stop()

	priority := 1000

	err := server.StartServer(New, version, priority)
	if err != nil {
		log.Fatal(err) //nolint:gocritic
	}
}
