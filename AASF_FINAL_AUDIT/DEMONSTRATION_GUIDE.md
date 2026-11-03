# AASF END-TO-END DEMONSTRATION GUIDE (PHASE 4)
**Project:** Adaptive Agentic Security Firewall (AASF)  
**Auditor:** Technical Demonstration & Verification Team  
**Date:** November 02, 2026  
**Status:** Runnable Demonstration Manual  

---

## 1. Overview & Demonstration Architecture

The AASF demonstration suite verifies the core in-process firewall runtime without relying on external web browsers, mock UIs, or live cloud network calls.

The executable demonstration script is located at:
[`AASF_FINAL_AUDIT/demo/runnable_demo.py`](file:///c:/Users/karis/repo/ai-agent-permission-firewall/AASF_FINAL_AUDIT/demo/runnable_demo.py)

It executes the six canonical runtime pathways:
- **Demo A:** Authorized Action (Policy PERMIT $\to$ ALLOW $\to$ Execution $\to$ State Update)
- **Demo B:** Prohibited Action (Policy PROHIBIT $\to$ DENY $\to$ Execution Blocked)
- **Demo C:** Human Oversight (Policy UNDETERMINED $\to$ REVIEW $\to$ Approval $\to$ Execution)
- **Demo D:** Stale Review Protection (State drift detection during review)
- **Demo E:** Monitor Timeout & Fallback (Monitor timeout $\to$ Fail-closed REVIEW)
- **Demo F:** Multi-Step Distributed Attack Sequence (4-step exfiltration blocked at Step 4)

---

## 2. Environment Setup & Prerequisites

### Prerequisites
- Python 3.11+
- Virtual environment with project dependencies:
  ```bash
  pip install pydantic>=2.7.0 rfc8785>=0.1.4 pyyaml>=6.0
  ```

### Running the Demonstration
To run all six demonstrations sequentially with full execution logging:
```bash
python AASF_FINAL_AUDIT/demo/runnable_demo.py
```

To run a specific demonstration (e.g. Demo F):
```bash
python AASF_FINAL_AUDIT/demo/runnable_demo.py --demo F
```

---

## 3. Directory Layout of Demonstration Artifacts

```
AASF_FINAL_AUDIT/demo/
├── README.md                      # Demonstration quickstart guide
├── runnable_demo.py               # Standalone, runnable Python demonstration
├── sample_inputs/                 # JSON inputs for Demos A through F
│   ├── demo_a_authorized.json
│   ├── demo_b_prohibited.json
│   ├── demo_c_review.json
│   ├── demo_d_stale.json
│   ├── demo_e_monitor_fail.json
│   └── demo_f_multistep.json
├── actual_outputs/                # Machine-readable JSON outputs
│   ├── demo_a_output.json
│   ├── demo_b_output.json
│   ├── demo_c_output.json
│   ├── demo_d_output.json
│   ├── demo_e_output.json
│   └── demo_f_output.json
└── execution_traces/              # Detailed terminal execution logs
    ├── trace_authorized.txt
    ├── trace_prohibited.txt
    ├── trace_review_lifecycle.txt
    └── trace_multistep_attack.txt
```

---

## 4. Verification Checklist for Evaluators

When running each demonstration, confirm the following technical evidence:

1. **Demo A (Authorized):**
   - Check that `response.status == "EXECUTED"`.
   - Check that `response.result.has_value == True`.
   - Check that the session state sequence advanced from 0 to 1.
   - Verify that an `AuditRecord` of type `EXECUTED` exists in `AuditStore`.

2. **Demo B (Prohibited):**
   - Check that `response.status == "DENIED"`.
   - Check that `response.decision == "DENY"`.
   - Check that `reason_codes` contains `"POLICY_PROHIBIT:R1-no-confidential-external-export"`.
   - **Crucial:** Confirm that the underlying tool function was **never invoked**.

3. **Demo C (Review Approval):**
   - Check that initial call returns `status == "PENDING_REVIEW"` with a valid `ticket_id`.
   - Verify that calling `resolve_review(ticket_id, "APPROVE")` updates status to `"EXECUTED"`.
   - Verify that ticket status is marked `ReviewStatus.EXECUTED` to prevent duplicate approvals.

4. **Demo D (Stale Approval):**
   - Confirm that attempting to approve a review ticket after session state has mutated is flagged.

5. **Demo E (Monitor Timeout):**
   - Check that `monitor_verdict == "UNKNOWN"`.
   - Confirm that the firewall fails closed to `"PENDING_REVIEW"`, never allowing execution.

6. **Demo F (Multi-Step Sequence):**
   - Steps 1, 2, and 3 must succeed (`status == "EXECUTED"`).
   - Step 4 (`execute_export`) must be rejected (`status == "DENIED"`).
   - Verify that `state.bound_resource` and `state.destination` correctly tracked the composition of prior steps.

---
*End of Demonstration Guide.*

