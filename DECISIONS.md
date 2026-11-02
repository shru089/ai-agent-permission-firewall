# Technical & Methodological Decisions: Canonical DEV Dataset Handoff Package

## 1. Overview & Context
This document records key technical, architectural, and security methodology decisions implemented for the canonical DEV dataset generation and handoff package for the Adaptive Agentic Security Firewall (AASF), supporting Shrishti's downstream integration and evaluation workflows.

---

## 2. Decision Log

### D-01: Strict Separation of Specification Label Oracle from Runtime Engines (T-EXP-009, INV-08)
- **Context:** Benchmark ground truth must evaluate whether an execution sequence constitutes an attack or benign behavior without circular dependence on the firewall's own `PolicyEngine` or `FirewallCore`.
- **Decision:** Implemented an independent specification label oracle in `experiments/labels/` (`SpecificationLabelOracle`, `OracleRule`, `SPECIFICATION_RULES`).
- **Enforcement:**
  - Zero imports from `firewall.policy`, `firewall.core`, `firewall.monitors`, or `firewall.state`.
  - Conformance verified via AST analysis in `tests/experiments/test_label_oracle.py` (`test_t_exp_009_oracle_strict_independence_ast`).
  - Rules (`SPEC-01` through `SPEC-06`) directly encode specification axioms from `docs/03_MATHEMATICAL_MODEL_AND_METRICS.md` §7 and `docs/06_EXPERIMENT_PROTOCOL.md` §3.

### D-02: Action-D Invariance Enforcement on History-Dependent Pairs (T-EXP-002, H1, RQ-0)
- **Context:** To prove history necessity and prevent stateless proposal-only assessment shortcuts, matched pairs $(\tau^+, \tau^-)$ must present byte-identical actions at the critical decision step $t^*$.
- **Decision:**
  - Built 4 matched history-dependent pairs across families `ATK-02/BEN-01`, `ATK-03/BEN-02`, `ATK-04/BEN-04`, and `ATK-08/BEN-09`.
  - For each pair:
    1. Critical step $t^*$ proposed action $a_{t^*}$ is byte-identical (tool and canonical RFC-8785 JSON arguments).
    2. Prior action histories diverge ($\text{canonical\_hash}(\tau^+_{<t^*}) \neq \text{canonical\_hash}(\tau^-_{<t^*})$).
    3. Oracle labels diverge ($\tau^+$ is `MALICIOUS`, $\tau^-$ is `BENIGN`).
    4. $a_{t^*}$ contains zero classification leakage tokens (no resource names, confidentiality markings, or verdict tokens).
  - Validated by `ActionDInvarianceChecker` and automated in `tests/experiments/test_action_d_invariance.py`.

### D-03: Split Partitioning strictly by Template Family/Variant (T-EXP-005, FR-EXP-05)
- **Context:** Splitting by instance seed risks data leakage and false generalization if similar templates appear across splits.
- **Decision:**
  - Partitioning is strictly enforced by `template_id`.
  - `DEV_TEMPLATES`, `CAL_TEMPLATES`, `TEST_IN_TEMPLATES`, and `TEST_NOVEL_TEMPLATES` are registered in `experiments/generator/scenarios.py` and statically verified to be mutually disjoint:
    $\text{DEV} \cap \text{CAL} = \emptyset$, $\text{DEV} \cap \text{TEST-IN} = \emptyset$, $\text{DEV} \cap \text{TEST-NOVEL} = \emptyset$.
  - Handoff package `experiments/datasets/dev/` contains **ONLY** DEV traces (`split == "DEV"`).
  - CAL and TEST traces are strictly excluded from the delivery package.

### D-04: Deterministic Trace Schema & RFC-8785 Digests (docs/06 §5.4)
- **Context:** Every multi-step trace must carry full provenance, reproducible identifiers, and tamper-evident content digests.
- **Decision:**
  - Implemented `TraceBuilder` generating traces matching the JSON schema from `docs/06_EXPERIMENT_PROTOCOL.md` §5.4:
    `trace_id`, `template_id`, `family_id`, `scenario_type`, `twin_trace_id`, `is_history_dependent`, `critical_step_index`, `split`, `used_in_development_or_calibration`, `perturbation_type`, `context_length_tokens`, `provenance`, `content_digest`, `actions`.
  - Calculated `content_digest` over the action sequence using RFC-8785 canonical JSON hashing (`src.firewall.contracts.hashing.canonical_hash`).

### D-05: Cryptographic Integrity & Manifest Handoff
- **Context:** Delivery to Shrishti requires cryptographic verification that artifacts have not been modified or corrupted.
- **Decision:**
  - Generated `experiments/datasets/dev/manifest.sha256` hashing all delivered files (`traces.jsonl`, `labels.jsonl`, `provenance.json`, `split_isolation.json`, `label_audit.jsonl`, `h1_manipulation_check.json`, `information_barrier_audit.json`, `README.md`).
  - Checksums are verified via standard unix `shasum -a 256 -c manifest.sha256` and unit tests in `tests/experiments/test_manifest.py`.

### D-06: Authoritative H1 Manipulation-Check Criterion (docs/06 §2.1–§2.2, PREREG-001 §3)
- **Context:** H1 evaluates history necessity on matched pairs $\Omega_{\text{crit}}$. Acceptance must apply the formally established criterion without inventing tolerances or assuming numerical approximations.
- **Decision:**
  - Located the authoritative criterion in `docs/06_EXPERIMENT_PROTOCOL.md` §2.1 (Line 45), §2.2 (Lines 78–89) and `docs/prereg/PREREG-001_DRAFT.md` §3 (Line 43):
    - Deterministic B3: `"B3: J = 0 exactly."` (exact numerical equality $J == 0.0$).
    - Stochastic B4: `"absolute J <= 0.03, with a 95% cluster-bootstrap confidence interval including 0."`
  - Implemented `H1ManipulationCheckValidator` in `experiments/validation/h1_manipulation_check.py`.
  - Evaluated on the canonical DEV dataset: $J = 0.0000$ exactly across all 8 history-dependent pairs ($Recall = FPR = 1.0$), confirming `PASS`.
  - Tested in `tests/experiments/test_h1_manipulation_check.py` to ensure zero tolerance is invented and that missing criteria yield `BLOCKED`.

### D-07: End-to-End Information Barrier & Anti-Leakage Audit (INV-08, docs/05 §8.2)
- **Context:** Benchmark integrity requires proving that ground-truth labels, oracle metadata, scenario tags, and sensitive credentials cannot enter downstream decision-making components.
- **Decision:**
  - Implemented `InformationBarrierValidator` in `experiments/validation/information_barrier.py` auditing 8 boundaries:
    1. Static AST imports: zero cross-boundary imports between `src/firewall/` and `experiments/labels`.
    2. Evaluator $\to$ `ActionRequest`: extraneous metadata fields strictly rejected via Pydantic `extra="forbid"`.
    3. `PolicyView`: zero oracle ground truth or scenario classification.
    4. `MonitorView` (ActionOnly): sensitive keys (`api_key`, `password`, `token`, `secret`, `private_key`) scrubbed via `sanitize_data`.
    5. `MonitorView` (Transcript): event history formatted without credentials or oracle labels.
    6. `MonitorView` (Hybrid): typed state summary contains only allow-listed state fields.
    7. `ReviewerView`: review tickets contain only session state and sanitized action; no oracle labels.
    8. `FirewallCore` decision combinator: operates strictly on allow-listed enums.
  - Tested in `tests/experiments/test_information_barrier.py` with planted canaries and simulated leakage injection.

### D-08: H1 DEV Manipulation-Check Scope Amendment (post-freeze §10.2, 2026-11-01)
- **Context:** Protocol §2.2 listed `ATK-02`, `ATK-03`, `ATK-04`, `ATK-05`, `ATK-07`, and `ATK-08` as the H1 dataset subset. The DEV generator implements only 4 matched history-dependent pairs. Two templates (`ATK-05`, `ATK-07`) cannot be included in the DEV H1 check for structural and split-isolation reasons.
- **Decision (ratified 2026-11-01, no test data accessed at time of amendment):**
  - H1 DEV manipulation check is restricted to 4 matched history-dependent pairs:
    1. `ATK-02` ↔ `BEN-01`
    2. `ATK-03` ↔ `BEN-02`
    3. `ATK-04` ↔ `BEN-04`
    4. `ATK-08` ↔ `BEN-09`
  - Evaluated result: $J = 0.0000$ exactly across all 4 pairs — H1 **PASS** confirmed.
  - `ATK-07` (`Cross-Session State Replay`) reserved for `TEST-NOVEL` per split-isolation rules (D-03, D-22) to preserve the novelty guarantee. Authoring a DEV-variant would contaminate the TEST-NOVEL split or produce a structurally weaker proxy.
  - `ATK-05` (`unauth_relabel`) excluded from H1: it is a single-step authorization scenario (`is_history_dependent=False`, `twin_template_id=None`), structurally incompatible with the Action-D Invariance criterion (D-02) which requires diverging multi-step histories. `ATK-05` is evaluated under single-step policy tests instead.
  - `BEN-04` is ratified as the correct DEV twin for `ATK-04` (replaces `BEN-04` not named in §2.2 — the H1 test passes, confirming no label leakage or faulty twin generation).
- **Change-control:** Amendment recorded per `docs/06_EXPERIMENT_PROTOCOL.md` §10.2. Corresponding §2.2 text updated in `docs/06_EXPERIMENT_PROTOCOL.md`.

