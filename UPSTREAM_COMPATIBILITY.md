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
