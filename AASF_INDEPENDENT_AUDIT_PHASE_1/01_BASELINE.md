# 01_BASELINE: Phase 1 Independent Reproduction and Evidence Audit

**Audit Timestamp:** 2026-11-02T15:25:00+05:30  
**Auditor:** Independent Reproduction Auditor (AI Agent)  
**Repository:** `ai-agent-permission-firewall`  

---

## 1. Version Control & Environment State

### Git Metadata
- **Git Commit Hash:** `943559a466356d3536898f58ac9c594b03d4f418`
- **Current Branch:** `main`
- **Commit Subject:** `chore: clean up report directory prototypes and format demo script`
- **Working-Tree Status:** `CLEAN` (No uncommitted changes, no untracked application files)
- **Tracking Remote:** `origin/main` (ahead by 2 commits locally)

### Host Environment
- **Operating System:** Windows 10 / Windows 11 Enterprise (`nt`, build 10.0.26200-SP0)
- **Python Version:** `Python 3.11.9` (`tags/v3.11.9:de54cf5`, Apr 2 2024, 10:12:12) [MSC v.1938 64-bit AMD64]
- **Shell / Terminal:** PowerShell on Windows with Sandbox Bypass mode

### Dependency Inventory

| Package | Installed Version | Status | Role in AASF |
|---|---|---|---|
| `pydantic` | `2.7.1` | Installed | Core data contracts, immutable schemas, validation |
| `rfc8785` | `0.1.4` | Installed | Canonical JSON serialization for hashing |
| `pytest` | `9.1.1` | Installed | Primary test runner |
| `hypothesis` | `6.170.9` | Installed | Property-based invariant testing |
| `ruff` | `0.17.2` | Installed | Code formatting and linting |
| `mypy` | `2.4.0` | Installed | Static type verification |
| `matplotlib` | `3.10.8` | Installed | Chart and empirical visualization |
| `docx` (`python-docx`) | `1.2.0` | Installed | Report document compilation |
| `win32com` (`pywin32`) | Installed | Installed | Native Microsoft Word COM PDF automation |
| `hashlib`, `hmac` | Python stdlib | Built-in | SHA-256 digest engine and HMAC token generation |

---

## 2. Repository Structure & Boundary Separation

The repository is structured into distinct tiers:

```text
d:\Desktop\ai-agent-permission-firewall\
├── src/
│   ├── firewall/            <-- CANONICAL RUNTIME (Authoritative Production Code)
│   │   ├── audit/           <-- Tamper-evident cryptographic audit log
│   │   ├── cascade/         <-- Tiered advisory cascades & adapters
│   │   ├── contracts/       <-- Immutable Pydantic v2 schemas and enums
│   │   ├── decision/        <-- Pure decision combinator Delta
│   │   ├── executor/        <-- ControlledExecutor & TokenStore
│   │   ├── monitor/         <-- Advisory monitors & SafeMonitorWrapper
│   │   ├── oversight/       <-- ReviewService ticketing & state revalidation
│   │   ├── policy/          <-- Three-valued ABAC PolicyEngine
│   │   ├── state/           <-- StateEngine (Phi), views, evidence, registry
│   │   └── core.py          <-- Central FirewallCore orchestrator
│   └── fw/                  <-- Legacy / prototype simulation package
├── legacy/                  <-- Deprecated archival prototypes
├── tests/                   <-- Automated verification suite (415 tests)
│   ├── experiments/         <-- Dataset determinism, action-D invariance, split isolation
│   ├── golden/              <-- Frozen contract schema snapshots
│   ├── integration/         <-- End-to-end FirewallCore runtime tests
│   ├── invariants/          <-- Security invariants contracts & state checks
│   ├── property/            <-- Hypothesis property-based hashing tests
│   └── unit/                <-- Isolated subsystem unit tests
├── experiments/             <-- Benchmarks, datasets (DEV, CAL, TEST-IN, TEST-NOVEL), reports
├── docs/                    <-- Formal PRDs, architecture, protocol PREREG-001, threat model
├── AASF_FINAL_PROJECT_REPORT/ <-- Deliverable project report (.docx, .pdf, charts, diagrams)
└── AASF_INDEPENDENT_AUDIT_PHASE_1/ <-- Independent Audit Outputs (Current Workspace)
```

---

## 3. Canonical Component Mapping

The table below identifies the authoritative source files responsible for each core system component:

| Component Name | Authoritative Source File | Core Classes / Functions | Primary Responsibility |
|---|---|---|---|
| **FirewallCore** | `src/firewall/core.py` | `FirewallCore`, `RouteTrace` | Central in-process orchestration, session locking, vertical slice interception. |
| **PolicyEngine** | `src/firewall/policy/evaluator.py` | `PolicyEngine`, `create_default_stateful_policy()` | Three-valued attribute-based policy evaluation (`PERMIT`, `PROHIBIT`, `REVIEW`). |
| **Decision Combinator** | `src/firewall/decision/combinator.py` | `decide()`, `DecisionConfig` | Pure mathematical function $\Delta$ mapping policy, evidence, and monitors to `ALLOW`/`DENY`/`REVIEW`. |
| **Monitor Adapter** | `src/firewall/cascade/adapter.py` | `CascadeAdapter`, `HeuristicRuleCascade` | Heuristic tiered rejection cascade; routes fast path vs. monitor invocation. |
| **Semantic Monitor** | `src/firewall/monitor/base.py`, `mock.py`, `model_client.py` | `Monitor`, `SafeMonitorWrapper`, `DeterministicMockMonitor` | Advisory-only risk scoring with timeout and exception containment. |
| **Session State** | `src/firewall/contracts/models.py`, `src/firewall/state/engine.py` | `SessionState`, `apply_event()`, `initial_state()` | Monotonic state fold $\Phi(S_{n-1}, a_n, r_n)$ tracking action history and data taints. |
| **Hash Chain** | `src/firewall/audit/store.py`, `src/firewall/state/engine.py` | `AuditStore`, `AuditRecord`, `compute_state_hash()` | Sequential SHA-256 hash chaining over state transitions and audit logs. |
| **MonitorView** | `src/firewall/state/views.py` | `build_monitor_view()`, `build_reviewer_view()` | Information isolation barrier: redacts raw secrets, credentials, and sensitive records. |
| **ReviewService** | `src/firewall/oversight/service.py` | `ReviewService`, `ReviewTicket` | Human oversight ticketing, resolution tracking, and state-hash revalidation (`INV-05`). |
| **Execution Token Store** | `src/firewall/executor/tokens.py` | `TokenStore`, `TokenMetadata` | Single-use HMAC-SHA256 authorization token issuance, validation, and atomic consumption (`INV-06`). |
| **Controlled Tool Executor** | `src/firewall/executor/executor.py` | `ControlledExecutor`, `ToolRegistry` | Enforces token validity before tool invocation; only component with tool execution authority. |
| **Audit Store** | `src/firewall/audit/store.py` | `AuditStore`, `verify_chain()` | Tamper-evident append-only logging with full cryptographic continuity verification (`INV-09`). |

---

## 4. Legacy and Deprecated Module Audit

1. **`legacy/firewall/` and `legacy/fw/`:**
   - Contains deprecated initial prototypes from Phase 1/Phase 2 development.
   - Verified that neither `src/firewall/` nor `tests/` import from `legacy/`.
2. **`src/fw/`:**
   - Older simulation and orchestrator harness.
   - Retained for backwards compatibility with historical simulation scripts in `docs/research/`.
   - The canonical runtime under `src/firewall/` is completely standalone and imports zero dependencies from `src/fw/`.

---

## 5. Baseline Status Verdict

- **Baseline Established:** **SUCCESS**
- **Git Working Tree:** **CLEAN**
- **Canonical Architecture:** Clearly delineated under `src/firewall/`
- **Audit Environment:** Standardized on Python 3.11.9, Windows 10/11 x64, with all dependencies verified.

