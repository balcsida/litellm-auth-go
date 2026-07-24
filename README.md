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

Log in with a browser, or print the URL for manual/headless completion:

```sh
litellm-auth --base-url https://proxy.example.com login
litellm-auth --base-url https://proxy.example.com login --no-browser
litellm-auth --base-url https://proxy.example.com login --team team-engineering
```

Other commands are:

```sh
litellm-auth whoami
litellm-auth print-token
litellm-auth logout
```

`print-token` only reads a fresh local token; it never logs in, refreshes a
token, or makes a network request. Use `--base-url` when reading a token for a
specific proxy. It rejects a token issued by another normalized proxy URL.

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

## Credential storage and lifetime

The default token file is `~/.litellm/token.json`. On Unix, the store creates
the directory with private permissions and writes the file as `0600`; it also
rejects insecure existing file or directory modes. Treat the file and printed
token as secrets. Credentials are bound to their normalized issuer URL, so a
token cannot be loaded for a different proxy origin.

This protocol has no refresh or revocation operation. `logout` removes only the
local token file; revoke or rotate a server-side key through the LiteLLM proxy
when that is required. Log in again after a credential expires.

## Verification

The examples compile without an OpenAI SDK:

```sh
go test ./examples/...
```
