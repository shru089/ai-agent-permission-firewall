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
  - Generated `experiments/datasets/dev/manifest.sha256` hashing all delivered files (`traces.jsonl`, `labels.jsonl`, `provenance.json`, `split_isolation.json`, `label_audit.jsonl`, `README.md`).
  - Checksums are verified via standard unix `shasum -a 256 -c manifest.sha256` and unit tests in `tests/experiments/test_manifest.py`.
