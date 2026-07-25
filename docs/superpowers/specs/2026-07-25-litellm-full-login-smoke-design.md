# LiteLLM full-login smoke design

## Goal

Exercise `litellm-auth-go` against an actual LiteLLM installation in GitHub
Actions, including complete CLI SSO credential issuance. The job must be
self-contained, require no repository secrets, and run on pull requests.

## Design

Add one Ubuntu smoke job to the existing CI workflow. PostgreSQL and a
digest-pinned mock OIDC server run as job services. The job installs LiteLLM
from the commit pinned in `UPSTREAM_COMPATIBILITY.md`, configures its generic
OIDC integration and database, starts one proxy process, and waits for its
readiness endpoint.

The pinned LiteLLM revision permits generic SSO without an Enterprise license
while the database contains at most five users. Pinning is therefore part of
the test contract; updating LiteLLM requires rechecking both the private CLI
SSO endpoints and this license boundary.

Add one environment-gated Go smoke test. It:

1. Creates a real CLI SSO session with `Client.Start`.
2. Uses an HTTP client with a cookie jar to follow the verification URL through
   the mock OIDC authorization flow and LiteLLM callback.
3. Reads LiteLLM's completion form and submits its hidden browser token with
   the session's user code.
4. Calls `Client.PollOnce` and verifies a ready result containing a non-empty
   credential for the configured mock user.

The test skips when its smoke-test base URL is absent, so ordinary local
`go test ./...` runs remain unchanged. CI captures LiteLLM logs when startup or
the smoke test fails.

## Alternatives rejected

- An in-repository OIDC server would avoid a service image but add OAuth,
  signing, discovery, and token-endpoint code unrelated to this library.
- Keycloak would provide a fuller identity platform but require substantially
  more startup time and configuration for the same protocol coverage.
- Testing only start and pending poll would avoid OIDC and PostgreSQL but would
  not cover the requested full login or credential issuance.

## Verification

- Run the new smoke test first against an unavailable proxy and confirm the
  expected connection failure.
- Run the existing Go suite and static checks locally.
- Validate the workflow syntax.
- Run the GitHub Actions smoke job to prove the installed LiteLLM, PostgreSQL,
  mock OIDC provider, callback, completion, and credential poll work together.
