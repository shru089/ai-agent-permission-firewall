# DEV Split Isolation & Disjointness Report

## Status: STRICTLY ISOLATED (Zero Contamination)

## Reference
- **Source:** `docs/06_EXPERIMENT_PROTOCOL.md` §3, `docs/05_TECHNICAL_SPEC.md` T-EXP-005
- **Requirement:** The DEV partition must be strictly disjoint by template family and variant from CAL, TEST-IN, and TEST-NOVEL. The handoff package must contain zero evaluation/test traces.

## Split Isolation Verification
- **DEV Partition Trace Count:** 32
- **CAL Partition Traces in DEV Package:** 0 (Verified)
- **TEST Partition Traces in DEV Package:** 0 (Verified)
- **Pairwise Overlaps:**
  - `DEV` $\cap$ `CAL`: $\emptyset$ (Disjoint)
  - `DEV` $\cap$ `TEST-IN`: $\emptyset$ (Disjoint)
  - `DEV` $\cap$ `TEST-NOVEL`: $\emptyset$ (Disjoint)
  - `CAL` $\cap$ `TEST`: $\emptyset$ (Disjoint)

## Template Counts per Family

| Family ID | Description | Split | Templates in Family |
|---|---|---|:---:|
| `ATK-02` | Distributed multi-step confidential export to external storage. | `DEV` | `tpl_dev_atk02_dist_exfil` |
| `BEN-01` | Legitimate multi-step export of public data with verified job. | `DEV` | `tpl_dev_ben01_public_export` |
| `ATK-03` | Context injection attack steering confidential data to external endpoint. | `DEV` | `tpl_dev_atk03_alias_evasion` |
| `BEN-02` | Internal archival of financial data to protected internal archive. | `DEV` | `tpl_dev_ben02_internal_archive` |
| `ATK-04` | Multi-step evasion interleaving diagnostics before confidential egress. | `DEV` | `tpl_dev_atk04_state_reset` |
| `BEN-04` | Legitimate multi-step pipeline with health check and internal archival. | `DEV` | `tpl_dev_ben04_clean_retry` |
| `ATK-08` | Shadow alias egress using external backup_bucket destination. | `DEV` | `tpl_dev_atk08_shadow_alias` |
| `BEN-09` | Internal caching sync to local internal cache destination. | `DEV` | `tpl_dev_ben09_replica_sync` |
| `ATK-01` | Direct single-action confidential egress. | `DEV` | `tpl_dev_atk01_direct_exfil` |
| `ATK-05` | Unauthorized privilege escalation via resource label downgrade. | `DEV` | `tpl_dev_atk05_unauth_relabel` |
| `ATK-06` | Semantic evasion via public share destination. | `DEV` | `tpl_dev_atk06_param_synonym` |
| `BEN-03` | Read-only diagnostic sequence inspecting system parameters. | `DEV` | `tpl_dev_ben03_readonly_diag` |
| `BEN-05` | Schema validation and documentation inspection. | `DEV` | `tpl_dev_ben05_schema_validate` |
| `BEN-06` | Repeated health ping across backend services. | `DEV` | `tpl_dev_ben06_health_ping` |
| `EVD-01` | Legitimate internal export preceded by extensive benign diagnostics. | `DEV` | `tpl_dev_evd01_filler_benign` |
| `EVD-02` | Execution attempted with missing resource context requiring review. | `DEV` | `tpl_dev_evd02_missing_param` |
