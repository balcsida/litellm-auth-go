# LiteLLM upstream compatibility

This client tracks LiteLLM commit
`c2efe9e422b6ce62f0001d847d578d1e7d7ea6e3` (commit date 2026-05-15),
inspected on 2026-07-24.

The canonical upstream files inspected at that commit are:

- `litellm/proxy/client/cli/commands/auth.py`
- `litellm/proxy/management_endpoints/ui_sso.py`
- `tests/test_litellm/proxy/client/cli/test_auth_commands.py`

LiteLLM marks `/sso/cli/start`, `/sso/cli/poll/{key_id}`, and
`/sso/cli/complete/{login_id}` with `include_in_schema=False`. They are not in
the generated OpenAPI schema, so the Go compatibility tests are the contract.

The regression suite locks the upstream request paths, trailing-slash
normalization, polling-secret header, pending/ready and team-selection shapes,
and stored-token base-URL binding. It also covers safe diagnostics for
proxy/CLI version skew, a missing shared cache in multi-replica deployments,
corporate gateways returning non-JSON pages, retrying `429` but stopping on
other `4xx` responses, and accepting omitted `verification_uri_complete` and
`attribution_metadata` fields.

Reinspect all three pinned files before changing this contract or updating the
LiteLLM commit.

## Native CLI PKCE contract

`AuthenticatePKCE` relies on the discovery document at
`/.well-known/litellm-cli-auth`, added by BerriAI/litellm#37626 and released in
LiteLLM v1.99.0. The CI smoke job installs v1.99.0. The CLI SSO contract files
above were last inspected at the commit named at the top of this file.

## Identity-provider login

`AuthenticateOIDC` relies only on `litellm_jwtauth.issuers` (`issuer`,
`jwks_url`, `audience`, `disable_audience_validation`), available since
LiteLLM v1.99.0. No LiteLLM-side discovery is used; the issuer and client id
are configured on the client. The earlier draft of this feature depended on
BerriAI/litellm#35234, which was closed unmerged.
