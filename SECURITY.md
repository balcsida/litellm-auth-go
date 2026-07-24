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

Callers should avoid logging returned credentials and should pass an explicit
base URL when loading a token for a particular proxy.
