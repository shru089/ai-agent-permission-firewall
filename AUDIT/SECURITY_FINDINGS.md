# AASF Security Findings & Vulnerability Register

**Auditor:** Independent Security & Application Architecture Audit Team  
**Scope:** Runtime Firewall (`src/firewall/`), Execution Controls, Audit Chain, and Console Endpoints  
**Audit Date:** November 5, 2026  
**Status:** Documented & Verified (Awaiting Remediation Approval)  

---

## Vulnerability Summary Matrix

| ID | Title | Component | Severity | CVSS v3.1 | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **SEC-01** | Missing Evidence & Undetermined Policy Bypass on Review Approval | `FirewallCore.resolve_review()` | **High** | 7.5 | Verified |
| **SEC-02** | Unsigned In-Memory Capability Tokens Contrasting HMAC Claims | `TokenStore` & `AuthorizationToken` | **Medium** | 5.3 | Verified |
| **SEC-03** | Default Insecure Evidence Secret Accepted Without Warning | `FirewallCore.__init__` | **Medium** | 6.5 | Verified |
| **SEC-04** | Incomplete Audit Record Field Hashing (Metadata Tampering Blind Spot) | `AuditStore._compute_record_hash()` | **High** | 7.1 | Verified |
| **SEC-05** | Unauthenticated Remote Access & Client-Controlled Reviewer Identity | `src/console/server.py` | **High** | 8.2 | Verified |

---

## Detailed Vulnerability Profiles

### SEC-01: Missing Evidence & Undetermined Policy Bypass on Human Review Approval

#### 1. Vulnerability Details
- **Affected File:** `src/firewall/core.py`
- **Affected Function:** `FirewallCore.resolve_review()` (Lines 646–688)
- **CWE:** CWE-863 (Incorrect Authorization), CWE-285 (Improper Authorization)

#### 2. Root Cause
In `resolve_review()`, when a reviewer approves a ticket (`outcome="APPROVE"`), `policy_engine.evaluate(action=action, state=state, registry=self.registry)` is executed. However, the check only blocks execution if `policy_result.verdict == PolicyVerdict.PROHIBIT`:
```python
if policy_result.verdict == PolicyVerdict.PROHIBIT:
    # return DENY ...
```
If the policy evaluation returns `PolicyVerdict.EVIDENCE_MISSING` (e.g., action requires a cryptographic receipt or prior clearance that is absent) or `PolicyVerdict.UNDETERMINED` (policy cannot determine safety without monitor analysis), the code falls through:
```python
# f. If policy is not PROHIBIT and state is fresh, issue token and execute
token = self.token_store.issue_token(...)
envelope, receipt = self.executor.execute(...)
```

#### 3. Exploit Scenario
An agent requests a privileged export tool where policy specifies Rule R1 (requires signed clearance evidence). The request is escalated to human review as `EVIDENCE_MISSING`. A human reviewer approves the ticket without supplying the prerequisite evidence. Because the verdict is `EVIDENCE_MISSING` rather than `PROHIBIT`, the firewall mints a valid execution token and dispatches the action to the host environment, completely bypassing the evidence verification requirement.

#### 4. Proposed Minimal Remediation Plan
In `FirewallCore.resolve_review()`:
1. Verify that `policy_result.verdict == PolicyVerdict.PERMIT`.
2. If `policy_result.verdict == PolicyVerdict.EVIDENCE_MISSING`: Deny execution with reason code `EVIDENCE_MISSING_ON_APPROVAL`.
3. If `policy_result.verdict == PolicyVerdict.UNDETERMINED`: Deny execution with reason code `UNDETERMINED_ON_APPROVAL`.
4. Only allow execution if the policy explicitly re-evaluates to `PERMIT` under fresh session state.
5. Add comprehensive unit tests in `tests/unit/test_security_fixes.py` verifying each non-PERMIT outcome.

---

### SEC-02: Authorization Capability Tokens Contrasting HMAC Claims

#### 1. Vulnerability Details
- **Affected Files:** `src/firewall/executor/tokens.py`, `src/firewall/contracts/models.py`
- **Affected Classes:** `TokenStore`, `AuthorizationToken`
- **CWE:** CWE-345 (Insufficient Verification of Data Authenticity)

#### 2. Root Cause
Documentation repeatedly asserts that AASF issues "HMAC-SHA256 cryptographically signed tokens" preventing token forgery. In reality, `AuthorizationToken` contains only metadata and a UUID nonce. `TokenStore` acts as an in-memory dictionary lookup. While it enforces single-use semantics (`self._consumed`), it computes no cryptographic signature. Any component with access to the Python object can instantiate an `AuthorizationToken` without possession of a signing secret.

#### 3. Exploit Scenario & Architectural Impact
In a distributed or multi-process deployment where `ControlledExecutor` resides in a separate service or container, an attacker could forge tokens without holding the firewall's private key. In the current single-process prototype, structural encapsulation prevents unauthorized calls from the sandboxed agent, but documentation claims of cryptographic token signatures are inaccurate.

#### 4. Proposed Minimal Remediation Plan
1. Add an optional HMAC-SHA256 signature generator and verifier to `TokenStore`:
   - `signature = hmac.new(key, canonical_token_bytes, hashlib.sha256).hexdigest()`
   - Store signature in token or verify during `consume_token()`.
2. Add a `signature: Optional[str] = None` field to `AuthorizationToken`.
3. If operating in capability mode, clearly document in `README.md` and architecture docs that token security relies on in-memory single-use capability tracking under Assumption A-01, with cryptographic signature verification available for out-of-process dispatch.
4. Add adversarial tests covering:
   - Forged token IDs
   - Tampered `action_hash`
   - Tampered `state_head_hash`
   - Replay / double-consumption attempts
   - Expired tokens

---

### SEC-03: Hardcoded Insecure Default Evidence Key in Production Configuration

#### 1. Vulnerability Details
- **Affected Files:** `src/firewall/core.py`, `src/firewall/state/evidence.py`
- **Line Reference:** `src/firewall/core.py:133`
- **CWE:** CWE-798 (Use of Hard-coded Credentials), CWE-1188 (Insecure Default Initialization)

#### 2. Root Cause
`FirewallCore.__init__` accepts `verifier: Optional[EvidenceVerifier] = None`. When `None`, it defaults silently to:
```python
self.verifier = verifier or HmacEvidenceVerifier(key=b"firewall_default_key")
```
No environment check (e.g., `AASF_ENV=production`) prevents this known static key from being used.

#### 3. Exploit Scenario
In a production deployment, if an operator does not explicitly configure a custom `EvidenceVerifier`, any adversary knowing `b"firewall_default_key"` can generate valid HMAC receipts for forged tool execution evidence, allowing malicious actions to mutate session state taints.

#### 4. Proposed Minimal Remediation Plan
1. Introduce an explicit configuration parameter: `production_mode: bool = False` (or check `os.environ.get("AASF_ENV") == "production"`).
2. If `production_mode is True` and no explicit key or verifier is supplied (or if key equals `b"firewall_default_key"`), raise an explicit `SecurityConfigurationError` and fail closed.
3. Allow `b"firewall_default_key"` only when `production_mode is False` (default test/demo mode).
4. Add regression tests validating fail-closed behavior on missing or default production keys.

---

### SEC-04: Incomplete Audit Record Field Hashing (Metadata Tampering Blind Spot)

#### 1. Vulnerability Details
- **Affected File:** `src/firewall/audit/store.py`
- **Affected Functions:** `AuditStore._compute_record_hash()`, `AuditStore.verify_chain()`
- **CWE:** CWE-353 (Missing Support for Integrity Check), CWE-345

#### 2. Root Cause
`_compute_record_hash` computes:
```python
def _compute_record_hash(self, prev_hash: str, payload: dict[str, Any]) -> str:
    canonical_bytes = canonical_json(payload, reject_floats=False)
    hasher = hashlib.sha256()
    hasher.update(prev_hash.encode("utf-8"))
    hasher.update(canonical_bytes)
    return hasher.hexdigest()
```
The hash chain binds only `prev_hash` and `payload`. It completely omits:
- `rec_id`
- `session_id`
- `seq`
- `type` (record type)
- `mono_ns` (timestamp)

#### 3. Exploit Scenario
An insider or compromised process alters an audit record in-place:
```python
rec.type = "POLICY_PERMIT"  # was "POLICY_PROHIBIT"
rec.seq = 999
rec.session_id = "other_session"
```
When `audit_store.verify_chain(session_id)` is executed, it only verifies `_compute_record_hash(rec.prev_hash, rec.payload) == rec.hash`. Because `rec.type`, `rec.seq`, and `rec.session_id` were not hashed, the integrity check returns `True`. The log modification is completely undetected!

#### 4. Proposed Minimal Remediation Plan
1. Update `_compute_record_hash` to bind all security-critical record fields:
   ```python
   def _compute_record_hash(
       self,
       prev_hash: str,
       session_id: str,
       seq: int,
       record_type: str,
       payload: dict[str, Any],
       mono_ns: int,
   ) -> str:
       record_data = {
           "prev_hash": prev_hash,
           "session_id": session_id,
           "seq": seq,
           "type": record_type,
           "payload": payload,
           "mono_ns": mono_ns,
       }
       canonical_bytes = canonical_json(record_data, reject_floats=False)
       return hashlib.sha256(canonical_bytes).hexdigest()
   ```
2. Update `verify_chain()` to recompute using all fields and verify strict monotonic continuity:
   - Check `rec.seq == expected_seq` (detect record deletion and reordering).
   - Check `rec.session_id == session_id` (detect cross-session record injection).
   - Check `rec.hash == computed_hash`.
3. Add tampering regression tests covering:
   - Modifying record `type`
   - Modifying record `seq`
   - Modifying record `session_id`
   - Modifying record `mono_ns`
   - Modifying record `payload`
   - Record deletion / gap detection
   - Record reordering

---

### SEC-05: Unauthenticated Console Endpoints & Client-Controlled Identity

#### 1. Vulnerability Details
- **Affected File:** `src/console/server.py`
- **Affected Endpoints:** `/api/reviews/{ticket_id}/resolve`, `/api/audit/tamper-demo`, `/api/action/submit`
- **CWE:** CWE-306 (Missing Authentication for Critical Function), CWE-287 (Improper Authentication)

#### 2. Root Cause
1. All console endpoints lack authentication tokens, session cookies, or API keys.
2. `CORSMiddleware` is configured with `allow_origins=["*"]` and `allow_credentials=True`.
3. `ResolveReviewPayload` accepts `reviewer_id` from the untrusted HTTP request body without verification.
4. `run_security_console.py` can bind to `--host 0.0.0.0`, exposing administrative review approval to the local network.

#### 3. Exploit Scenario
If an operator starts the console on an intranet (`--host 0.0.0.0`), any network attacker or malicious browser tab executing cross-origin requests can approve pending human review tickets, execute privileged tools, and trigger audit tampering endpoints.

#### 4. Proposed Minimal Remediation Plan
1. Enforce local-only host binding by default (`127.0.0.1` / `localhost`); reject or require explicit `--allow-remote` flag with mandatory API key token authentication when binding to external interfaces.
2. Restrict `CORSMiddleware` origins from wildcard `["*"]` to local loopback origins (`http://localhost:8000`, `http://127.0.0.1:8000`).
3. Add a simple API key bearer-token dependency or administrative secret header (`X-AASF-Reviewer-Token` / `X-AASF-Admin-Key`) for mutation endpoints (`/api/reviews/...`, `/api/audit/...`).
4. Ensure the local interactive demonstration remains zero-friction out of the box when running on localhost.
5. Add unit and integration tests verifying endpoint access control.

