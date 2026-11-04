"""
AASF Project Report - Chapter 5: Project Analysis.
Covers:
5.1 Existing System Analysis
5.2 Critical Limitations of Existing Systems
5.3 Proposed System Architecture and Advantages
5.4 Multidimensional Feasibility Analysis
5.5 Use Case Analysis and Actor Modeling
5.6 Functional Decomposition
5.7 Data Flow Analysis (Level 0 DFD)
5.8 System Workflow and Request Lifecycle
"""

import os
from docx import Document
from styles import add_chapter_title, add_h1, add_h2, add_p, add_bullet, add_table, add_figure, add_callout, add_page_break

def add_chapter5(doc: Document):
    add_chapter_title(doc, "CHAPTER 5", "PROJECT ANALYSIS")
    
    # 5.1 Existing System Analysis
    add_h1(doc, "5.1", "Existing System Analysis")
    add_p(doc,
        "In current commercial and open-source agent execution environments (such as LangChain, AutoGen, CrewAI, and OpenAI Assistants), "
        "agents interact directly with tool interfaces via unmediated application function calls or through perimeter API gateways. "
        "When an agent deliberates and emits a structured tool call (e.g., `execute_export(destination='s3://external')`), the runtime "
        "environment evaluates whether the agent possesses API-level credentials for the tool. If the credentials are valid, the invocation "
        "is dispatched directly to the host operating system, network socket, or database connector."
    )
    add_p(doc,
        "Where security controls do exist, they typically manifest as coarse-grained, static permissions: an agent is either granted or "
        "denied access to a tool for the entire lifetime of its deployment. If a tool is flagged as sensitive, contemporary systems employ "
        "crude binary gating—either blocking the tool entirely or interrupting execution to request human approval for every single invocation."
    )

    # 5.2 Critical Limitations of Existing Systems
    add_h1(doc, "5.2", "Critical Limitations of Existing Systems")
    add_p(doc, "Our technical analysis identifies five catastrophic vulnerabilities inherent to existing agent architectures:")
    add_bullet(doc, 
        "Existing systems maintain zero memory of preceding actions. They cannot correlate a current export action with a read action performed "
        "three steps earlier. The evaluated history-manipulation scenarios test whether monitors account for this preceding context.",
        "1. Complete Causal Blindness (Stateless Evaluation):"
    )
    add_bullet(doc, 
        "Stateless systems are incapable of tracking information taint. When an agent reads confidential records, its cognitive context becomes "
        "tainted with confidential data. Existing architectures do not propagate this taint to subsequent file-staging or export operations.",
        "2. Absence of Dynamic Taint Propagation:"
    )
    add_bullet(doc, 
        "Some execution engines dispatch calls using persistent system credentials without a single-use authorization token. This design can "
        "increase exposure to replay and authorization-binding risks.",
        "3. Lack of Execution Tokenization:"
    )
    add_bullet(doc, 
        "Mandatory human review for sensitive actions can increase review workload. This study measures review rates on its benchmark splits; it does not evaluate a deployed production review queue.",
        "4. Acute Human Oversight Fatigue:"
    )
    add_bullet(doc, 
        "Application audit logs in existing platforms are stored as plain JSON records or standard database rows. A compromised agent or "
        "host process can alter, truncate, or delete historical log entries, destroying non-repudiation and forensic auditability.",
        "5. Tamperable Post-Hoc Audit Logs:"
    )

    # 5.3 Proposed System Architecture and Advantages
    add_h1(doc, "5.3", "Proposed System Architecture and Advantages")
    add_p(doc,
        "The Adaptive Agentic Security Firewall (AASF) replaces unmediated execution with an authoritative, in-process security kernel. "
        "FirewallCore mediates submitted requests through the configured execution interface, folds them into a deterministic state vector, evaluates stateful ABAC policies, consults "
        "tiered advisory monitors, and issues cryptographically signed, single-use execution tokens. Table 5.1 provides a structured comparison "
        "between the existing paradigm and the proposed AASF architecture."
    )
    
    headers_t51 = ["Architectural Feature", "Existing Agent Runtimes", "Proposed AASF Architecture", "Impact on Security Posture"]
    data_t51 = [
        ["Interception Mechanism", "Direct, unmediated tool dispatch", "In-process FirewallCore mediation", "Configured agent tool actions are routed through the firewall gateway."],
        ["State Tracking", "Stateless / per-action isolation", "Deterministic Monotonic State Fold (Phi)", "Correlates multi-step workflows; tracks confidential taints (INV-02)."],
        ["Policy Logic", "Binary (Allow / Deny)", "Three-Valued Lattice (PERMIT / PROHIBIT / REVIEW)", "Expressive risk handling; accommodates dynamic human oversight."],
        ["AI Risk Monitoring", "None or direct LLM judge authority", "Advisory-only tiered cascades (B4/B5/P1)", "Compared with B3, B6 review rate decreased 75% on TEST-IN and 100% on TEST-NOVEL."],
        ["Execution Authorization", "Static API keys / Bearer tokens", "Single-use action/state-bound authorization tokens", "Token redemption checks include action binding, expiry, and single-use consumption."],
        ["Review Revalidation", "Unverified execution on approval", "State-head re-check on approval (INV-05)", "Review approval is revalidated against the session state head."],
        ["Audit Integrity", "Plain text / Relational DB logs", "Append-only SHA-256 hash chain", "Audit records are linked by hashes and the chain can be verified."],
    ]
    col_w_t51 = [1.3, 1.4, 1.8, 1.5]
    add_table(doc, headers_t51, data_t51, "Table 5.1", "Comparative Feature Matrix: Conventional Controls vs. Proposed AASF", col_w_t51)

    # 5.4 Multidimensional Feasibility Analysis
    add_h1(doc, "5.4", "Multidimensional Feasibility Analysis")
    add_p(doc, "A comprehensive feasibility study was conducted across four critical dimensions:")
    add_bullet(doc, 
        "AASF is implemented in Python and uses Pydantic data models and standard-library cryptographic primitives. Canonical evaluator decision latency "
        "is reported by arm and split in Chapter 8. The separate synthetic-request CLI microbenchmark is not combined with evaluator measurements.",
        "1. Technical Feasibility:"
    )
    add_bullet(doc, 
        "AASF uses tiered heuristic and monitor consultation. In the benchmark summary, B6 review rate relative to B3 decreased 75% on TEST-IN "
        "and 100% on TEST-NOVEL. These results are limited to the evaluated traces; operational costs were not measured.",
        "2. Economic Feasibility:"
    )
    add_bullet(doc, 
        "The system introduces a structured ReviewService that integrates seamlessly into enterprise security operations. Human reviewers "
        "receive high-fidelity context packets containing exact state diffs, policy rule IDs, and risk explanations, transforming oversight "
        "from an overwhelming chore into an actionable, high-efficiency workflow.", 
        "3. Operational Feasibility:"
    )
    add_bullet(doc, 
        "The project was rigorously partitioned into nine phases with clear milestone boundaries, successfully completing all engineering, "
        "benchmarking, and formal reporting deliverables within the 10-month capstone timeline.", 
        "4. Schedule Feasibility:"
    )

    # 5.5 Use Case Analysis and Actor Modeling
    add_h1(doc, "5.5", "Use Case Analysis and Actor Modeling")
    add_p(doc,
        "System functionality is modeled around four primary actors interacting with the AASF runtime:"
    )
    add_bullet(doc, "The autonomous entity generating tool invocation requests (ActionRequest) to achieve its programmed goals.", "1. Autonomous Agent:")
    add_bullet(doc, "Defines ABAC access control rules, resource classification schemas, tool risk registries, and evidence requirements.", "2. Security Administrator:")
    add_bullet(doc, "Inspects flagged review tickets, evaluates redacted context, and issues APPROVE or REJECT oversight decisions.", "3. Human Reviewer:")
    add_bullet(doc, "Performs independent mathematical audits of the hash-chained audit store to verify integrity and compliance.", "4. Compliance Auditor:")
    add_p(doc, "Figure 5.1 depicts the comprehensive UML Use Case diagram mapping actor interactions to core system use cases.")
    
    # Embed Fig 5.1 Use Case Diagram
    use_case_path = os.path.join("AASF_FINAL_PROJECT_REPORT", "diagrams", "fig5_1_system_use_case_diagram.png")
    add_figure(doc, use_case_path, "Figure 5.1", "Comprehensive AASF System Use Case Diagram with Multi-Actor Modeling", width_in=5.8)

    # 5.6 Functional Decomposition
    add_h1(doc, "5.6", "Functional Decomposition")
    add_p(doc, "The functional architecture of AASF decomposes into six discrete, loosely coupled subsystems:")
    add_bullet(doc, "Ingests raw agent requests, validates JSON schemas against CanonicalAction contracts, and acquires exclusive session locks.", "Subsystem 1: Interception & Session Gateway:")
    add_bullet(doc, "Maintains the session state vector, applying the deterministic folding function Phi to update history and taint classifications.", "Subsystem 2: Deterministic State Engine:")
    add_bullet(doc, "Evaluates candidate actions against attribute rules, evidence receipts, and resource classifications. Evidence HMAC verification is separate from authorization tokens.", "Subsystem 3: Stateful Policy Engine:")
    add_bullet(doc, "Executes multi-tiered heuristic checks (B4) and offline model assessments (B5/P1) across isolated MonitorView projections.", "Subsystem 4: Advisory Monitor Cascade:")
    add_bullet(doc, "Pure mathematical decider Delta synthesizing policy, evidence, and advisory verdicts into ALLOW, DENY, or REVIEW.", "Subsystem 5: Invariant Decision Combinator:")
    add_bullet(doc, "Manages review ticketing, state revalidation, single-use authorization tokens, and controlled tool execution. Evidence HMAC verification is separate.", "Subsystem 6: Oversight & Token Execution Engine:")

    # 5.7 Data Flow Analysis (Level 0 DFD)
    add_h1(doc, "5.7", "Data Flow Analysis (Level 0 DFD)")
    add_p(doc,
        "Figure 5.2 illustrates the Context-Level Data Flow Diagram (DFD Level 0). It highlights the strict boundary separation: "
        "configured interactions between the Agent, Security Administrator, Human Reviewer, and External Environment pass through "
        "the central AASF in-process firewall gateway."
    )
    
    # Embed Fig 6.6 DFD Level 0 Context
    dfd0_path = os.path.join("AASF_FINAL_PROJECT_REPORT", "diagrams", "fig6_6_dfd_level_0.png")
    add_figure(doc, dfd0_path, "Figure 5.2", "Context-Level Data Flow Diagram (DFD Level 0) of In-Process Interception", width_in=5.8)

    # 5.8 System Workflow and Request Lifecycle
    add_h1(doc, "5.8", "System Workflow and Request Lifecycle")
    add_p(doc, "The lifecycle of an action request within AASF progresses through seven deterministic stages:")
    add_bullet(doc, "The agent submits an ActionRequest; the gateway parses arguments and computes action_hash = SHA256(canonical_json).", "Stage 1 (Submission):")
    add_bullet(doc, "The session lock is acquired; current SessionState head hash is retrieved from the registry.", "Stage 2 (Session Lock):")
    add_bullet(doc, "PolicyEngine evaluates the action against active ABAC rules. If strictly prohibited, DENY is returned immediately.", "Stage 3 (Policy Evaluation):")
    add_bullet(doc, "If policy permits, the request follows the configured advisory cascade; monitor consultation depends on the decision path.", "Stage 4 (Cascade Routing):")
    add_bullet(doc, "DecisionCombinator computes Delta(P, E, M). If REVIEW, a ticket is created and session state transitions to BUSY.", "Stage 5 (Decision Synthesis):")
    add_bullet(doc, "Upon ALLOW, TokenStore issues a single-use authorization token. ControlledExecutor validates the token before invoking the tool.", "Stage 6 (Execution):")
    add_bullet(doc, "Execution results are captured; StateEngine folds the event into the session state; AuditStore appends the hash-chained record.", "Stage 7 (State Fold & Audit):")

    add_page_break(doc)
