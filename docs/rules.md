# Repository Rules

**Project:** AI Agent Permission Firewall  
**Purpose:** Define enforceable import boundaries, security-sensitive ownership, and test-set isolation rules for the repository.

> These are proposed repository rules. Add the checks to CI and enforce ownership through `CODEOWNERS` once the repository structure is finalized.

---

## 1. Import boundaries enforced in CI

These rules protect the separation between runtime enforcement, monitoring, and experimental ground truth.

### Rule 1 — Runtime code must not depend on experiments or labels

Code under `src/firewall/` must never import from `experiments/` or `labels/`.

**Reason:** Runtime enforcement must not depend on experimental machinery or ground-truth labels. Labels must never influence runtime decisions.

### Rule 2 — The label oracle must be independent of the policy engine

Code under `experiments/oracle/` must never import `firewall.policy`.

**Reason:** Ground-truth labels must be derived independently from the experiment specification, not from the policy implementation being evaluated. Otherwise, policy bugs could be reproduced in the labels and make evaluation circular.

### Rule 3 — Monitors receive a prepared view, not internal state

`firewall.monitor` may import only `firewall.schemas`; it must not import internal modules from `firewall.state`.

**Reason:** The state layer prepares an explicit, allow-listed monitor view. This information boundary prevents monitors from accessing hidden state or implementation details that are not part of their declared input.

### Rule 4 — Tool credentials and tool calls belong only to the executor

Only `executor/` may hold tool credentials or directly call modules under `tools/`.

**Reason:** All tool execution must pass through the controlled executor after authorization. Other components must not be able to bypass the gateway and decision pipeline.

### Rule 5 — Shared domain types have one canonical definition

No code outside `schemas/` may define its own action, decision, or state types.

**Reason:** Duplicate definitions drift over time and create inconsistent interpretations of security-critical data. Shared types must have one source of truth.

---

## 2. Ownership and review responsibilities

Use `CODEOWNERS` to require review from the responsible owner for changes to the following areas.

| Folder or files | Owner | Responsibility |
|---|---|---|
| `schemas/` | All four team members | Shared contracts; changes require cross-team review. |
| `policy/`, `config/policy_*`, `config/registry.yaml` | Karishma | Policy rules, registry configuration, and permission semantics. |
| `interceptor/`, `executor/`, `tools/sim/`, CI configuration | Akshat | Runtime interception, controlled execution, simulated tools, and CI enforcement. |
| `state/`, `monitor/`, experiment runner, `metrics.py`, `stats.py` | Shrishti | Observable state, runtime risk monitoring, experiment execution, and evaluation. |
| `oversight/`, `audit/`, `labels/`, and later the dashboard | Snehal | Human oversight, audit records, label storage, and dashboard. |
| `decision/` | Karishma and Akshat, with Shrishti reviewing | Final decision semantics and integration with policy and execution. |
| Test-set files under `experiments/datasets/test/` and any off-repository test-set storage | Akshat and Snehal | Test-set construction, protection, and separation from monitor development. |

Ownership indicates responsibility for review; it does not grant permission to bypass the project's security rules or test-set protections.

---

## 3. Test-set isolation

- Ground-truth labels must be stored separately from runtime inputs and monitor views.
- Runtime components and monitors must not read test labels.
- The experiment oracle must label scenarios from the written policy specification and scenario facts, independently of the policy engine implementation.
- Test-set authorship and access must follow the experiment protocol.
- Test data must not be used for prompt tuning, threshold selection, or rule development.
- Changes to test scenarios, labels, or the oracle must be reviewed and recorded.
- Any test-set exposure or leakage must be documented; affected results must not be presented as an untouched held-out evaluation.

---

## 4. CI enforcement checklist

CI should fail when any of the following is detected:

- [ ] A runtime module imports from `experiments/` or `labels/`.
- [ ] The experiment oracle imports the policy engine.
- [ ] A monitor imports internal state modules rather than consuming the prepared monitor view.
- [ ] A non-executor module directly calls tools or accesses tool credentials.
- [ ] An action, decision, or state type is redefined outside the canonical schemas package.
- [ ] Required `CODEOWNERS` review is missing for a protected path.

Prefer AST-based Python import checks over plain text searches, so comments and string literals do not create false positives. Add targeted tests for indirect imports and import aliases where practical. Tool-call and credential boundaries may require a combination of static checks, code review, and tests; a simple import checker alone cannot prove that secrets are never accessed or that no dynamic bypass exists.

---

## 5. Path consistency note

Before implementing these rules, agree on one canonical package layout and use it consistently across code, tests, documentation, CI, and `CODEOWNERS`.

The current technical specification uses some different names, including `src/fw/contracts/`, `src/fw/monitors/`, `src/fw/tools_sim/`, and `src/fw/experiments/`, whereas these rules use `src/firewall/`, `schemas/`, `monitor/`, `tools/sim/`, and a top-level `experiments/` directory.

**Do not implement path-based CI checks until this naming difference is resolved.** The security intent of the rules should remain unchanged regardless of the final directory names.
