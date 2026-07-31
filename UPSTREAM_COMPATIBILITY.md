# LiteLLM upstream compatibility

This client tracks LiteLLM commit
`6e26087cf407995b3b54f7ca4c845f6988b83626` (commit date 2026-07-30),
inspected on 2026-07-31.

The native OIDC contract additionally tracks the unmerged
[BerriAI/litellm#35234](https://github.com/BerriAI/litellm/pull/35234) at head
`dd6bdd19e35fb8298cc8a0fa44c29fd6ca369af3`. Re-pin it once that PR merges.

The canonical upstream files inspected at that commit are:

- `litellm/proxy/client/cli/commands/auth.py`
- `litellm/proxy/management_endpoints/ui_sso.py`
- `tests/test_litellm/proxy/client/cli/test_auth_commands.py`
- `litellm/types/proxy/discovery_endpoints/ui_discovery_endpoints.py` (PR #35234)
- `litellm/proxy/discovery_endpoints/ui_discovery_endpoints.py` (PR #35234)
- `litellm/litellm_core_utils/native_oidc_validation.py` (PR #35234)

## Native OIDC discovery contract

`/.well-known/litellm-ui-config` carries an optional `native_oidc` object with
exactly three fields: `issuer`, `client_id`, and `scopes`. Unknown fields are
rejected, matching the proxy's `extra="forbid"` model.

`issuer` is an issuer identifier, not a metadata URL. The provider document is
located by removing a single trailing slash and appending
`/.well-known/openid-configuration`, and the document is rejected unless its
own `issuer` equals the advertised one byte-for-byte. Both sides therefore
apply no normalization: not case, port, percent-encoding, or trailing slash.

An earlier draft of this client read `native_oidc.discovery_url`. That name was
never served by any LiteLLM build; the field is `issuer`.

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
