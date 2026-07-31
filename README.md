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

`login` discovers native OIDC metadata from the proxy and uses a public-client
Authorization Code + PKCE flow by default. The client needs a loopback redirect
URI (`http://127.0.0.1:<ephemeral-port>/callback`) registered with the provider;
it never uses a client secret. Configure LiteLLM to validate the issued JWT and
map it to a virtual key, for example:

```yaml
general_settings:
  enable_jwt_auth: true
  litellm_jwtauth:
    user_id_jwt_field: sub
    virtual_key_claim_field: sub
    unregistered_jwt_client_behavior: auto_register
    issuers:
      - issuer: https://idp.example.com
        jwks_url: https://idp.example.com/jwks
        disable_audience_validation: true
```

The proxy's public `/.well-known/litellm-ui-config` metadata advertises
`native_oidc.issuer`, `native_oidc.client_id`, and `native_oidc.scopes`. The
issuer is the trust anchor: this client appends
`/.well-known/openid-configuration` to it to locate the provider document, and
rejects that document unless its `issuer` matches byte-for-byte.
LiteLLM verifies and maps the JWT; this client does not verify its signature.

Choose a flow explicitly when needed:

```sh
litellm-auth --base-url https://proxy.example.com login
litellm-auth --base-url https://proxy.example.com login --flow browser
litellm-auth --base-url https://proxy.example.com login --flow device
litellm-auth --base-url https://proxy.example.com login --flow litellm-sso
litellm-auth --base-url https://proxy.example.com login --no-browser
```

`auto` is the default: it uses browser OIDC first, falling back to device
authorization only if it cannot bind the local listener before opening a
browser. `--no-browser` selects device authorization when native metadata is
available. Native OIDC flows do not support `--team`; `litellm-sso` preserves
the existing LiteLLM team selection flow. `auto` uses LiteLLM SSO only when
native metadata is absent, and never switches flows after authentication starts.

Other commands are:

```sh
litellm-auth whoami
litellm-auth print-token
litellm-auth logout
litellm-auth import-token
```

### Additional credential sources

Use `import-token` to store a token
from an environment variable, rotating file, stdin, or an external helper:

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

`print-token` reads a fresh local token. For an expired native OIDC credential,
it refreshes at the OIDC token endpoint and atomically saves the replacement
before printing it. It remains network-free for LiteLLM SSO and imported
credentials. Use `--base-url` when reading a token for a specific proxy. It
rejects a token issued by another normalized proxy URL.

| Setting | Meaning |
| --- | --- |
| `--base-url` | LiteLLM proxy URL. It takes precedence over `LITELLM_PROXY_URL`. |
| `LITELLM_PROXY_URL` | Default proxy URL. `login` otherwise uses `http://localhost:4000`. |
| `--token-file` | Credential file; default is `~/.litellm/token.json`. |
| `--timeout` | Total login timeout; default is 10 minutes. |
| `--allow-insecure-http` | Permits non-loopback HTTP for development only. |
| `--verbose` | Shows safe polling progress. |
| `login --flow` | `auto` (default), `browser`, `device`, or `litellm-sso`. |
| `login --no-browser` | Uses device authorization for native OIDC; prints the LiteLLM SSO URL and code otherwise. |
| `login --team` | Selects a LiteLLM team ID without prompting; unavailable for native OIDC. |

## Credential storage and lifetime

The default token file is `~/.litellm/token.json`. On Unix, the store creates
the directory with private permissions and writes the file as `0600`; it also
rejects insecure existing file or directory modes. Treat the file and printed
token as secrets. Credentials are bound to their normalized issuer URL, so a
token cannot be loaded for a different proxy origin.

Native OIDC credentials refresh automatically through `print-token`; LiteLLM
SSO and imported tokens do not. `logout` removes only the local token file;
revoke or rotate server-side credentials through the provider or LiteLLM proxy.

## Verification

The examples compile without an OpenAI SDK:

```sh
go test ./examples/...
```

## License

MIT. See [`LICENSE`](LICENSE).
