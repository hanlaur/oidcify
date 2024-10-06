# oidcify: OIDC plugin for Kong Gateway

OpenID Connect (OIDC) plugin for [Kong Gateway](https://github.com/Kong/kong), written in Go using Kong Plugin Development Kit.

This project is not affiliated with or otherwise sponsored by Kong, Inc.
This project is not related to OpenID connect plugin by Kong, Inc.

## Features

* OIDC Authorization Code Flow, with PKCE support
* Cookie-based session storage
* Bearer token authentication based on JWT ID token
* Sets group information in Kong context so that Kong ACL plugin can perform authorization based on groups
* Mapping of ID token claims to HTTP headers

## Required Kong version

Kong 3.8.0. Do not use the plugin with older Kong versions.

## Installation

Download the release archive from [Releases](https://github.com/hanlaur/oidcify/releases) page.

Place binary `oidcify` in `/usr/local/bin/`. 

Set following environment variables before starting Kong:

```shell
export KONG_PLUGINS="bundled,oidcify"
export KONG_PLUGINSERVER_NAMES="oidcify"
export KONG_PLUGINSERVER_OIDCIFY_QUERY_CMD="/usr/local/bin/oidcify -dump"
export KONG_PLUGINSERVER_OIDCIFY_START_CMD="/usr/local/bin/oidcify"
```

Configure the required configuration options for the plugin in kong plugin configuration.

## Configuration

Plugin supports the following configuration inputs:

| Option                     | Description                                                                                                                                                                                                                        | Default Value            | Required |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------ | -------- |
| `issuer`                   | OIDC Issuer URL. Example: `https://oidc.issuer.internal/`.  Will be used to formulate the URL for OIDC discovery document. Must match issuer values in the ID token.                                                               |                          | x        |
| `client_id`                | OIDC Client ID for OIDC Authorization Code Flow.                                                                                                                                                                                   |                          | x        |
| `client_secret`            | OIDC Client Secret. This value must be kept secret.                                                                                                                                                                                |                          | x        |
| `redirect_uri`             | OIDC redirect URI. For example `https://myserver.internal/cb`                                                                                                                                                                      |                          | x        |
| `consumer_name`            | Defines the Kong Consumer that will be set as authenticated consumer for a successful request. Example: `oidcuser`. The consumer must be defined in Kong.                                                                          |                          | x        |
| `cookie_hash_key_hex`      | Secret key used for cookie HMAC authentication. Must be cryptographically strong, 32 hex characters (256 bits). This value must be kept secret. If not set, random value is generated at startup.                                  | randomized on startup    | See note |
| `cookie_block_key_hex`     | Secret key used for cookie encryption. Must be cryptographically strong, 32 hex characters (256 bits). This value must be kept secret. If not set, random value is generated at startup.                                           | randomized on startup    | See note |
| `ca_cert_files`            | Array of PEM files to load as accepted TLS CA certificates. Example: `["/etc/oidcify/tlsca/internalca.pem"]`. If not defined, then system certificate pool is used.                                                                |                          |          |
| `static_provider_config`   | If defined, instead of OIDC discovery, configuration from this dictionary parameter is used. Dictionary keys: `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, `jwks_uri`, `id_token_signing_alg_values_supported` |                          |          |
| `groups_claim`             | Name of the ID token claim to retrieve user group memberships from. Claim must contain an array of string values. Groups are passed to other plugins via Kong context `authenticated_groups` variable.                             | `groups`                 |          |
| `scopes`                   | The scopes to request in the authorization code flow. You must include `openid` as one of the values. Example: `["openid", "profile", "email", "groups"]`                                                                          | `["openid"]`             |          |
| `use_pkce`                 | Use PKCE in the Authorization Code Flow. It is recommended to always use PKCE, if the OIDC provider supports it.                                                                                                                   | `true`                   |          |
| `use_userinfo`             | Defines whether to call userinfo endpoint to collect additional claims for the purposes of `headers_from_claims` functionality.                                                                                                    | `false`                  |          |
| `bearer_jwt_allowed_auds`  | Allowed `aud` values when validating Authorization header Bearer token. By default Bearer JWT authentication is disabled. The `aud` may be same or different from the authorization code flow Client ID.                           | `[]` (no allowed ids)    |          |
| `bearer_jwt_allowed_algs`  | Allowed signing algorithms when validating Authorization header Bearer token.                                                                                                                                                      | `["RS256"]`              |          |
| `cookie_name`              | Name prefix for OIDC session cookie. Sequence number will be appended to support cookie splitting.                                                                                                                                 | `OIDCSESSION`            |          |
| `session_lifetime_seconds` | Session lifetime in seconds. By default, session life time follows ID token expiry. If set, session expires based on ID token `iat` plus the configured lifetime value. Applies to auth code flow only.                            | `0` (use ID token value) |          |
| `redirect_unauthenticated` | Defines handling of unauthenticated HTTP requests. When set to `true`, client is redirected to OIDC authorization code flow. When set to `false`, HTTP 401 (Unauthorized) is returned.                                             | `true`                   |          |
| `logout_path`              | Defines path that is used to trigger logout (i.e. deletion of session cookie).                                                                                                                                                     | `/logout`                |          |
| `post_logout_redirect_uri` | Defines URL where to redirect user after logout. If not defined, the logout path will not redirect user but instead display a message. Example: `https://myserver.internal/loggedout/`                                             |                          |          |
| `headers_from_claims`      | Defines rules to map ID token or Userinfo claims to HTTP headers for the upstream service. Example: `{ "X-Oidc-Email": "email" }`.                                                                                                 | `{}` (no mappings)       |          |
| `skip_already_auth`        | If set to `true`, plugin ignores (allows without authentication) requests that already have credential identifier set by higher priority auth plugin.                                                                              | `false`                  |          |

Note: For sessions to survive Kong restart or work in multi-instance environment, the cookie hash and block keys must be defined. To generate random values for keys, consider: `python3 -c "import secrets; print(secrets.token_hex(32))"`

When using Kong ACL plugin, set `always_use_authenticated_groups: true` in ACL plugin configuration to use the groups set by this plugin. If not set, Kong ACL plugin will use groups defined for the consumer. For more detail see Kong documentation.

## Important notes

* Configured `cookie_hash_key_hex` and `cookie_block_key_hex` values must be kept secret and rotated periodically. A person knowing the secrets can forge a session cookie. Also, `client_secret` should be kept secret.
* Always use the plugin in combination with Kong ACL plugin and allow access only to defined groups. This provides additional protection layer.
* Test your configuration carefully. This is especially important when using a combination of multiple authn/authz related plugins.
* Access to kong logs should be protected as logs may contain security sensitive information from OIDC message exchanges.
* Session refresh using refresh token is not supported.
* Any changes in user profile at the provider during session life time are not reflected to the session.

## Session storage

Session information is stored in encrypted client-side cookie. Because there is no server side session
database, consider the following:

* There is no way to end an individual session from the server side, other than waiting for the session
  to expire according to session lifetime. If required, as an emergency procedure, it is possible to invalidate all
  existing sessions by changing the cookie hash and block key in the plugin configuration.
* Session cookie size can grow large depending on amount of data contained in OIDC tokens or OIDC UserInfo.
  The plugin automatically splits the data in multiple cookies if required, but you may need to allow larger
  size of HTTP headers in Kong and in the upstream service.

## Development notes

### Tests

Tests include both pure module tests and also integration tests with actual Kong. Integration tests require docker
compose environment with kong and pre-built oidcify. To run all tests:

```shell
# build oidcify
make

# Restart the compose environment with the fresh build
cd testenv/
docker compose down
docker compose up -d
cd ..

# wait for compose to initialize, and run tests
make test

# shutdown compose env
cd testenv
docker compose down
```

### Debugging

To run the plugin locally for development and debugging use, see example in `localenv/`. You must have kong installed
locally, and you must prepare `oidc.env` file that exports environment variables referenced in `kong-local.yml` that
defined the OIDC provider you want to use.

## License information

See file [NOTICE](NOTICE) for copyright information and file [LICENSE](LICENSE) for license text.

## Dependencies

Under the hood, this project utilizes many open-source Go dependencies. See [go.mod](go.mod) for a list.
Dependency license texts are included in the release archives as collected automatically by
the [go-licenses](https://github.com/google/go-licenses) tool. Should any license information be missing
from the archives, consult the dependency home page.
