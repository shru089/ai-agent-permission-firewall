# Gateway, Orchestration, and Executor Integration Audit

## Status

Inspection only. No implementation changes were made.

## Canonical package

`src/firewall/` is the active canonical package.

Evidence:

- All runtime modules and tests import from `firewall`.
- `src/fw/` imports from `firewall`.
- `src/fw/__init__.py` contains `import firewall`.

## Package roles

| Area | File | Status |
|---|---|---|
| Core orchestrator | `src/firewall/core.py` | Present |
| Cascade adapter | `src/firewall/cascade/adapter.py` | Present |
| Controlled executor | `src/firewall/executor/executor.py` | Present |
| Authorization tokens | `src/firewall/executor/tokens.py` | Present |
| Policy engine | `src/firewall/policy/evaluator.py` | Present |
| Policy rules | `src/firewall/policy/rules.py` | Present |
| State engine | `src/firewall/state/engine.py` | Present |
| Registry | `src/firewall/state/registry.py` | Present |
| Monitor views | `src/firewall/state/views.py` | Present |
| Audit store | `src/firewall/audit/store.py` | Present |
| Review service | `src/firewall/oversight/service.py` | Present |

## Current architecture

There is no separate `gateway.py` or `router.py`.

`FirewallCore` appears to act as the current gateway and orchestrator.

```text
ActionRequest
   -> FirewallCore
   -> PolicyEngine / state checks
   -> CascadeAdapter when semantic assessment is required
   -> Decision combinator
   -> ControlledExecutor
   -> AuditStore
```

## Integration questions to verify next

1. Does `FirewallCore` call `CascadeAdapter` for every request that reaches semantic assessment?
2. Does `DENY` stop execution before the executor is invoked?
3. Does `REVIEW` prevent execution until an approved review token exists?
4. Does `ALLOW` generate an exact-action authorization token?
5. Does the executor verify the token before running the tool?
6. Does malformed, timed-out, or UNKNOWN monitor output result in `REVIEW`?
7. Are there tests proving each of these behaviors?

## Next implementation task

After reviewing `FirewallCore.evaluate` and the existing integration tests, add or verify one mocked test:

A malformed deep-monitor response must produce `REVIEW`, never `ALLOW`.

## Limitations

This audit is based on file listings and import searches only.

It does not yet prove runtime behavior. The next step is to inspect `FirewallCore.evaluate`, `CascadeAdapter`, and `ControlledExecutor`, then run the existing tests.