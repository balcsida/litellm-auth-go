# Authentication sources and binders

## Model

A `Source` acquires a credential. A `Binder` decides where that credential is
placed. An `Authenticator` can apply multiple source/binder pairs to one
request.

## Sources

### LiteLLM CLI SSO

Use `NewSSOSource` with the existing `Client` and `AuthenticateOptions`.
The adapter caches a fresh SSO credential and reauthenticates when the cached
credential is no longer fresh (including the expiry safety margin) or after an
explicit `Invalidate` call.

### Static

Use `NewStaticSource`. Mark long-lived keys with `NonExpiring: true`, or
provide `ExpiresAt`. Tokens with a JWT `exp` claim derive their expiry locally.

### Environment

Use `NewEnvSource`. The variable is read on every request, so rotation is
observed without rebuilding the HTTP client.

### Rotating file

Use `NewTokenFileSource`. The file is read on every request. One trailing LF
or CRLF is accepted. The source never logs file contents. The dual-auth
example intentionally relies on the delegated user's JWT `exp` claim; opaque
rotating files must instead configure `ExpiresAt` or `NonExpiring`.

### External command

Use `NewExecSource`. The helper is executed directly without a shell. Its
stdout must be exactly one JSON object:

```json
{
  "token": "secret",
  "token_type": "Bearer",
  "expires_at": "2026-07-25T18:00:00Z",
  "non_expiring": false,
  "issuer": "https://issuer.example.com",
  "subject": "user-123",
  "scopes": ["litellm.invoke"]
}
```

Set either `expires_at` or `non_expiring`, unless the token is a JWT with an
`exp` claim. Diagnostics belong on stderr, but the library never relays helper
stderr to callers. Helpers inherit no environment unless it is explicitly
allowlisted through `ExecSourceConfig.AllowedEnv`.

## Binders

- `NewBearerHeader("Authorization")`
- `NewBearerHeader("x-litellm-api-key")`
- `NewRawHeader("X-API-Key")`
- `NewPrefixedHeader("Authorization", "token")`
- `NewMCPBearerHeader("github")`
- `NewA2ABearerHeader("research-agent")`

## Dual authentication

Use one binding for the LiteLLM gateway key and another for the delegated user
token:

```go
authenticator, err := litellmauth.NewAuthenticator(
	litellmauth.Binding{Source: gateway, Binder: gatewayBinder},
	litellmauth.Binding{Source: user, Binder: userBinder},
)
```

## CLI token import

```sh
litellm-auth --base-url https://proxy.example.com import-token \
  --from-env LITELLM_API_KEY --non-expiring

litellm-auth --base-url https://proxy.example.com import-token \
  --from-file /var/run/secrets/token --non-expiring

printf '%s\n' "$LITELLM_API_KEY" | \
  litellm-auth --base-url https://proxy.example.com import-token \
  --from-stdin --non-expiring

litellm-auth --base-url https://proxy.example.com import-token \
  --from-exec /usr/local/bin/corp-token-helper \
  --exec-arg issue --exec-arg litellm \
  --exec-env PATH --exec-env HTTPS_PROXY
```

The CLI never accepts the token itself as an argument. Helper paths and
arguments must also be non-secret because operating systems may expose process
arguments to other local users.
