# litellm-auth-go

`litellm-auth-go` authenticates Go applications and a small CLI with a
LiteLLM proxy's browser-based CLI SSO flow. It returns the LiteLLM API key
issued for the signed-in user and selected team.

## Prerequisites

Use a LiteLLM proxy with SSO configured and support for the CLI SSO endpoints.
At the pinned upstream version, these endpoints are beta/experimental and are
excluded from its OpenAPI schema; see
[UPSTREAM_COMPATIBILITY.md](UPSTREAM_COMPATIBILITY.md) for the exact upstream
commit and contract.

For a proxy with multiple replicas, the login session must live in a shared
auth cache (for example Redis). If LiteLLM reports an invalid CLI login session
and asks for a shared cache, configure that shared cache before retrying; a
browser callback and a poll request may otherwise reach different replicas.

## Library

Create a client for the proxy URL and use `OnSession` to open the verification
URL in the browser. The complete example is
[`examples/browser-login`](examples/browser-login).

```go
client, err := litellmauth.New("https://proxy.example.com")
if err != nil {
	return err
}
credential, err := client.Authenticate(ctx, litellmauth.AuthenticateOptions{
	OnSession: func(_ context.Context, session litellmauth.Session) error {
		return browser.OpenURL(session.VerificationURL.String())
	},
})
```

For headless environments, do not open a browser. Print the verification URL
and user code, then let the user open it elsewhere. Set `TeamID` when the
application already knows the team; otherwise `SelectTeam` can choose from the
proxy-provided teams. See [`examples/manual-login`](examples/manual-login).

```go
credential, err := client.Authenticate(ctx, litellmauth.AuthenticateOptions{
	TeamID: "team-engineering",
	OnSession: func(_ context.Context, session litellmauth.Session) error {
		fmt.Printf("Open %s\nCode: %s\n", session.VerificationURL, session.UserCode)
		return nil
	},
})
```

### Authorization code + PKCE (LiteLLM >= 1.99)

Proxies that publish `/.well-known/litellm-cli-auth` accept native clients
through the OAuth 2.1 authorization code flow with PKCE (the flow behind
`lite login --pkce`). The proxy is the authorization server: the client
registers itself dynamically, the user signs in and picks a team on the
proxy's consent page, and the proxy mints the same per-user credential
`lite login` mints, together with a rotating refresh token.

```go
credential, err := client.AuthenticatePKCE(ctx, litellmauth.PKCEOptions{
	OnSession: func(_ context.Context, session litellmauth.PKCESession) error {
		return browser.OpenURL(session.AuthorizeURL.String())
	},
})
```

Before it expires, renew the credential without a browser and persist the
result; the proxy rotates the refresh token on every renewal:

```go
renewed, err := client.RefreshPKCE(ctx, stored)
if errors.Is(err, litellmauth.ErrRefreshRejected) {
	// revoked or replaced by a newer login: run AuthenticatePKCE again
}
```

`RevokePKCE` revokes the refresh token server-side (RFC 7009) so a logout is
more than deleting a file. `ErrPKCEUnsupported` is returned when the proxy
does not publish the contract; fall back to `Authenticate`.

Every endpoint in the discovery document must share the proxy's origin, the
callback is a literal `127.0.0.1` loopback listener, the OAuth `state` is
compared in constant time, and no request follows redirects, so the code,
verifier, and refresh token can only ever be posted to the proxy the client
was created for.

### Identity-provider login (OIDC)

A client can also sign the user in at an OpenID Connect identity provider and
send the provider's `id_token` to LiteLLM as the bearer. The client needs a
public OIDC client (no secret) with the loopback redirect URI
`http://127.0.0.1:<port>/callback` registered. Endpoints come from the issuer's
`/.well-known/openid-configuration`, and S256 PKCE is required.

```go
provider := litellmauth.OIDCProvider{
	Issuer:   "https://idp.example.com",
	ClientID: "litellm-cli",
	Scope:    "openid profile email offline_access",
}
credential, err := client.AuthenticateOIDC(ctx, litellmauth.OIDCOptions{
	Provider: provider,
	OnSession: func(_ context.Context, session litellmauth.PKCESession) error {
		return browser.OpenURL(session.AuthorizeURL.String())
	},
})

// Without a browser, use the device authorization grant instead.
credential, err = client.AuthenticateOIDCDevice(ctx, litellmauth.OIDCDeviceOptions{
	Provider: provider,
	OnAuthorization: func(_ context.Context, auth litellmauth.DeviceAuthorization) error {
		fmt.Printf("Open %s\nCode: %s\n", auth.VerificationURI, auth.UserCode)
		return nil
	},
})
```

`client.Refresh` renews PKCE and OIDC credentials. `NewRefreshingSource` wraps a
`CredentialStore` such as a `tokenstore.FileStore`, refreshes when the
credential is stale (one refresh at a time), and saves the result.
`ErrLoopbackUnavailable` and `ErrOIDCDeviceUnsupported` report that no callback
port could be bound or that the provider has no device endpoint.

This client checks the `id_token` claims but not its signature; LiteLLM
verifies the signature. LiteLLM's JWT
authentication is an enterprise feature; see
[token_auth](https://docs.litellm.ai/docs/proxy/token_auth). Configure the
proxy with the issuer and the public client id as the audience:

```yaml
general_settings:
  enable_jwt_auth: true
  litellm_jwtauth:
    user_id_jwt_field: sub
    virtual_key_claim_field: sub
    unregistered_jwt_client_behavior: auto_register
    issuers:
      - issuer: https://idp.example.com
        jwks_url: https://idp.example.com/.well-known/jwks.json
        audience: <your public client id>
```

Per-issuer validation (`litellm_jwtauth.issuers`) exists since LiteLLM v1.99.0.
The proxy does no discovery: the issuer and client id are configured on the
client.

### Use the returned key

`credential.Key` is the API key. Pass it as the bearer token to a standard
`http.Client`; [`examples/use-token`](examples/use-token) loads the stored,
origin-bound credential and adds its `Authorization: Bearer ...` header in a
`RoundTripper`.

For an existing OpenAI-compatible Go client, use the same key and proxy base
URL. For example, an application already using `github.com/openai/openai-go`
would configure it as:

```go
client := openai.NewClient(
	option.WithAPIKey(credential.Key),
	option.WithBaseURL(credential.BaseURL+"/v1"),
)
```

Use the OpenAI-compatible route configured by the proxy; `/v1` is common. This
module does not require an OpenAI SDK.

## CLI

Install from this module's checkout:

```sh
go install ./cmd/litellm-auth
```

Log in with a browser, or print the URL for manual/headless completion:

```sh
litellm-auth --base-url https://proxy.example.com login
litellm-auth --base-url https://proxy.example.com login --no-browser
litellm-auth --base-url https://proxy.example.com login --team team-engineering
litellm-auth --base-url https://proxy.example.com login --flow pkce
litellm-auth --base-url https://proxy.example.com login --flow browser \
  --oidc-issuer https://idp.example.com --oidc-client-id litellm-cli
litellm-auth --base-url https://proxy.example.com login --flow device \
  --oidc-issuer https://idp.example.com --oidc-client-id litellm-cli
LITELLM_OIDC_ISSUER=https://idp.example.com LITELLM_OIDC_CLIENT_ID=litellm-cli \
  litellm-auth --base-url https://proxy.example.com login
```

`--flow pkce` uses the proxy's authorization code + PKCE flow (LiteLLM >= 1.99);
the team is chosen on the proxy's consent page. `--flow auto` (the default)
uses the identity provider when both issuer and client id are set: device with
`--no-browser`, otherwise browser, falling back to device only if no loopback
callback port can be bound before anything opens. Without OIDC settings it uses
the LiteLLM CLI SSO flow; setting only one of the two is an error. `browser`
and `device` require both settings, and
`--team` applies only to `litellm-sso` (and to `auto` without OIDC settings).
Once a flow has started, the CLI never switches to another. The default scope
includes `offline_access` so a refresh token is issued; for providers that
reject it (for example Google) pass `--oidc-scope "openid email"`, and refresh
then depends on the provider. Providers that require an exact redirect URI need
`--oidc-redirect-port`.

Other commands are:

```sh
litellm-auth whoami
litellm-auth print-token
litellm-auth logout
litellm-auth import-token
```

### Additional credential sources

Without OIDC settings, `login` uses the LiteLLM CLI SSO flow. Use
`import-token` to store a token from an environment variable, rotating file,
stdin, or an external helper:

```sh
litellm-auth --base-url https://proxy.example.com import-token \
  --from-env LITELLM_API_KEY --non-expiring
litellm-auth --base-url https://proxy.example.com import-token \
  --from-file /var/run/secrets/token --non-expiring
printf '%s\n' "$LITELLM_API_KEY" | \
  litellm-auth --base-url https://proxy.example.com import-token \
  --from-stdin --non-expiring
litellm-auth --base-url https://proxy.example.com import-token \
  --from-exec /usr/local/bin/corp-token-helper --exec-arg issue \
  --exec-env PATH --exec-env HTTPS_PROXY
```

See [authentication sources and binders](docs/AUTH_SOURCES.md) for lifetime
rules, external-helper schema, and library usage.

`print-token` never logs in. It prints a fresh local token; a stale credential
that carries a refresh token (identity-provider OIDC and proxy PKCE) is renewed
first and the replacement is saved atomically. LiteLLM SSO and imported tokens
are not refreshed and fail with the stale-credential error. Use `--base-url`
when reading a token for a specific proxy. It rejects a token issued by another
normalized proxy URL.

| Setting | Meaning |
| --- | --- |
| `--base-url` | LiteLLM proxy URL. It takes precedence over `LITELLM_PROXY_URL`. |
| `LITELLM_PROXY_URL` | Default proxy URL. `login` otherwise uses `http://localhost:4000`. |
| `--token-file` | Credential file; default is `~/.litellm/token.json`. |
| `--timeout` | Total login timeout; default is 10 minutes. |
| `--allow-insecure-http` | Permits non-loopback HTTP for development only. |
| `--verbose` | Shows safe polling progress. |
| `login --no-browser` | Does not launch a browser; prints the URL and code. |
| `login --team` | Selects a LiteLLM team ID without prompting. |
| `login --flow` | `auto` (default), `browser`, `device`, `pkce`, or `litellm-sso`. |
| `login --oidc-issuer` / `LITELLM_OIDC_ISSUER` | Identity provider issuer URL. The flag takes precedence. |
| `login --oidc-client-id` / `LITELLM_OIDC_CLIENT_ID` | Public OIDC client id. The flag takes precedence. |
| `login --oidc-scope` / `LITELLM_OIDC_SCOPE` | OIDC scopes; default `openid profile email offline_access`. |
| `login --oidc-redirect-port` | Loopback callback port to try, for exact redirect URIs. |

## Credential storage and lifetime

The default token file is `~/.litellm/token.json`. On Unix, the store creates
the directory with private permissions and writes the file as `0600`; it also
rejects insecure existing file or directory modes. Treat the file and printed
token as secrets. Credentials are bound to their normalized issuer URL, so a
token cannot be loaded for a different proxy origin.

The classic CLI SSO protocol has no refresh or revocation operation: after a
credential expires SSO users rerun `login` and imported-token users rerun
`import-token`. PKCE credentials additionally carry a refresh token, the
registered client id, and the proxy's token and revocation endpoints;
`RefreshPKCE` renews them and `RevokePKCE` revokes them server-side. OIDC
credentials carry the provider's refresh token when one was issued, and
`print-token` and `client.Refresh` renew them. `logout` revokes proxy PKCE
refresh tokens; for every other credential, including identity-provider ones,
it only deletes the local file and does not end the provider session.

## Verification

The examples compile without an OpenAI SDK:

```sh
go test ./examples/...
```

## License

MIT. See [`LICENSE`](LICENSE).
