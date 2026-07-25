# Security

`litellm-auth-go` treats the proxy, browser, network, response bodies, and
credential file as trust boundaries.

## Security contract

- HTTPS is required except for loopback login development; non-loopback HTTP
  requires explicit opt-in.
- Login redirects are rejected. A server-provided
  `verification_uri_complete` is used only when it is same-origin and does not
  contain the polling secret; otherwise the client builds the safe login URL.
- Polling secrets are sent only in `X-LiteLLM-CLI-Poll-Secret`. Public response
  fields that collide with the secret are rejected.
- Response bodies and credentials are not included in rendered errors or CLI
  diagnostics. Non-JSON gateway responses report only bounded metadata.
- Session and request deadlines are absolute. `429` and transient failures may
  retry within that boundary; other `4xx` responses stop.
- Stored credentials are bound to their normalized base URL. `print-token`
  does not authenticate, renew, or make a network request.
- Only `login` falls back to the localhost development proxy. Token-reading
  commands use the stored origin unless the caller explicitly supplies one.
- New credential directories and files use `0700` and `0600`. Existing paths
  with broader Unix permissions are rejected rather than silently repaired.
- Credential replacement is atomic, validates stored keys and metadata, and
  never persists login-session or polling secrets.
- Generic credentials fail closed when their expiry is unknown, unless the
  token has a JWT `exp` claim or is explicitly marked non-expiring.
- Environment and file sources are re-read for every acquisition.
- External credential helpers run without a shell, receive only allowlisted
  environment variables, have bounded execution time and output, and cannot
  expose stdout or stderr through library errors.
- Composite authentication acquires every credential before mutating a
  request, and the provided transport clones the request and headers.
- The CLI never accepts a token as an argument, and external-helper arguments
  are documented as non-secret process metadata.

Callers should avoid logging returned credentials and should pass an explicit
base URL when loading a token for a particular proxy.
