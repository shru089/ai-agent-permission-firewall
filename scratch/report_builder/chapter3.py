"""
AASF Project Report - Chapter 3: System Requirement Specification (SRS).
Covers:
3.1 Introduction
3.2 Functional Requirements (FR-01 to FR-12)
3.3 Non-Functional Requirements (NFR-01 to NFR-08)
3.4 Hardware Requirements
3.5 Software Requirements and Dependencies
3.6 Development Environment and Standards
3.7 Technology Stack Justification
3.8 Security Requirements and Invariant Catalog
3.9 Constraints and Assumptions
"""

from docx import Document
from styles import add_chapter_title, add_h1, add_h2, add_p, add_bullet, add_table, add_callout, add_page_break

def add_chapter3(doc: Document):
    add_chapter_title(doc, "CHAPTER 3", "SYSTEM REQUIREMENT SPECIFICATION")
    
    # 3.1 Introduction
    add_h1(doc, "3.1", "Introduction")
    add_p(doc,
        "The System Requirement Specification (SRS) establishes the formal engineering foundation for the Adaptive Agentic Security "
        "Firewall (AASF). It delineates the complete functional capabilities, non-functional performance benchmarks, hardware-software "
        "prerequisites, technological justifications, and mathematical security invariants that govern the design and intended implementation. "
        "Roadmap and traceability status labels cited here are historical planning text; requirements listed in this chapter are not, by themselves, evidence of implementation or verification."
    )

    # 3.2 Functional Requirements (FR-01 to FR-12)
    add_h1(doc, "3.2", "Functional Requirements (FR-01 to FR-12)")
    add_p(doc, "The requirements specification defines twelve functional requirements spanning request interception, state tracking, policy evaluation, and controlled execution:")
    
    frs = [
        ("FR-01: In-Process Tool Interception", "The firewall shall mediate agent tool invocation requests before control is dispatched to the configured executor."),
        ("FR-02: Deterministic State Folding", "The system shall implement a deterministic state-folding operator Phi(S, a, r) that updates the session state vector by folding incoming action requests and confirmed results into an immutable history chain."),
        ("FR-03: Three-Valued Policy Evaluation", "The Policy Engine shall evaluate candidate actions against active attribute-based access control rules, emitting exactly one of three formal verdicts: PERMIT, PROHIBIT, or REVIEW."),
        ("FR-04: Tiered Advisory Consultation", "The firewall shall support pluggable advisory monitors (rule-based heuristic cascades and offline LLM classifiers) capable of returning risk assessments without granting them direct authorization powers."),
        ("FR-05: Pure Decision Combination", "The Decision Combinator shall implement a pure, side-effect-free mathematical function Delta(P, E, M) mapping policy verdicts, evidence sufficiency, and monitor scores into an authoritative decision: ALLOW, DENY, or REVIEW."),
        ("FR-06: Authorization Token Issuance", "Upon reaching an ALLOW decision, the firewall shall issue a single-use authorization token bound to the action and relevant state. HMAC-SHA256 evidence verification is handled separately."),
        ("FR-07: Controlled Tool Execution", "The Controlled Executor shall validate authorization tokens for expiry, consumption, and action binding before executing tool actions."),
        ("FR-08: Single-Use Token Redemption", "The Token Store shall validate and mark tokens as consumed so that a consumed token cannot be reused."),
        ("FR-09: Human Oversight Ticketing", "When a REVIEW decision is generated, the Review Service shall create a persistent, cryptographically signed review ticket and transition the agent session into a suspended BUSY state."),
        ("FR-10: State-Hash Revalidation", "Upon human reviewer approval, the firewall shall compare the current session state hash with the hash recorded for the review before issuing a single-use execution token."),
        ("FR-11: Tamper-Evident Audit Logging", "The Audit Store shall record every received action, policy verdict, monitor score, combinator decision, and execution result in an append-only cryptographic hash chain where each record hashes the previous record's digest."),
        ("FR-12: Full Audit Chain Verification", "The system shall expose an automated verification method capable of mathematically validating the entire hash chain from the genesis record to the latest leaf, detecting any unauthorized bit-level modification."),
    ]
    for fr_title, fr_desc in frs:
        add_bullet(doc, fr_desc, fr_title + ":")

    # 3.3 Non-Functional Requirements (NFR-01 to NFR-08)
    add_h1(doc, "3.3", "Non-Functional Requirements (NFR-01 to NFR-08)")
    add_p(doc, "The requirements specification defines eight non-functional requirements. These are design targets, not claims of production readiness or measured satisfaction:")
    
    nfrs = [
        ("NFR-01: Preregistered Latency Targets", "The frozen protocol sets a B6 p95 target of 5 ms, a P1 fast-path p95 target of 10 ms, a P1 cascade-invoked p95 target of 600 ms, and a hard-timeout ceiling of 1,500 ms. H5 status and limitations are reported in Section 8.10."),
        ("NFR-02: Determinism and Reproducibility", "Given identical initial states and identical sequences of action requests, the state engine, policy evaluator, and decision combinator shall produce mathematically identical decision traces."),
        ("NFR-03: Fail-Closed Default Safety", "Any unexpected runtime exception, missing evidence attribute, unparseable payload, or monitor timeout shall immediately resolve to a safe fail-closed decision (DENY or REVIEW), never ALLOW."),
        ("NFR-04: Thread Safety and Concurrency", "The runtime firewall shall support concurrent multi-session execution without race conditions, data races, or token collisions using fine-grained session locking mechanisms."),
        ("NFR-05: Information Barrier Isolation", "Advisory monitors and human review views shall receive strictly redacted data projections (MonitorView), stripping raw sensitive database values, session secrets, and credentials (INV-10)."),
        ("NFR-06: Zero External Network Dependency", "The core firewall engine, state fold, and decision combinator shall execute completely in-process without requiring mandatory external network round-trips for baseline authorization."),
        ("NFR-07: Automated Test Suite", "The codebase shall include automated unit, integration, property-based, and invariant regression tests."),
        ("NFR-08: Type Safety and Static Linting", "The entire codebase shall enforce strict type safety under Mypy (zero typing errors) and conform to PEP 8 standards enforced by Ruff linting."),
    ]
    for nfr_title, nfr_desc in nfrs:
        add_bullet(doc, nfr_desc, nfr_title + ":")

    # 3.4 Hardware Requirements
    add_h1(doc, "3.4", "Hardware Requirements")
    add_p(doc, "The AASF runtime is engineered for high-performance in-process execution with minimal hardware footprints:")
    add_bullet(doc, "Quad-core x86_64 or ARM64 processor (2.0 GHz base clock or higher). Evaluated on 11th Gen Intel Core i7 / Apple Silicon M-series.", "Processor:")
    add_bullet(doc, "Minimum 8 GB RAM (16 GB recommended for running concurrent multi-agent simulation harnesses).", "System Memory:")
    add_bullet(doc, "Minimum 10 GB available solid-state storage (SSD) for repository code, Python virtual environments, and cryptographic audit logs.", "Disk Storage:")
    add_bullet(doc, "Standard TCP/IP network interface (required only when invoking optional remote LLM advisory monitors). Core firewall is network-independent.", "Networking:")

    # 3.5 Software Requirements and Dependencies
    add_h1(doc, "3.5", "Software Requirements and Dependencies")
    add_p(doc, "The software environment and declared dependency ranges are listed for reproducibility:")
    add_bullet(doc, "Microsoft Windows 11 (64-bit), Ubuntu Linux 22.04/24.04 LTS, or macOS 14+ Sonoma.", "Operating System:")
    add_bullet(doc, "Python 3.11.x (tested specifically with Python 3.11.9).", "Python Runtime:")
    add_bullet(doc, "Git version 2.40+ with SHA-256 commit verification support.", "Version Control:")

    # 3.6 Development Environment and Standards
    add_h1(doc, "3.6", "Development Environment and Standards")
    add_p(doc,
        "Development followed strict Test-Driven Development (TDD) protocols. Continuous Integration (CI) is managed via GitHub Actions "
        "configured with multi-stage verification jobs: (1) Ruff linting and formatting check; (2) Mypy static type verification across "
        "source and test suites; (3) pytest execution; and (4) dataset manifests and label-leakage checks."
    )

    # 3.7 Technology Stack Justification
    add_h1(doc, "3.7", "Technology Stack Justification")
    add_p(doc,
        "The following dependencies are declared in the repository configuration; their presence does not constitute an independent security or performance certification. "
        "Table 3.1 outlines the technology stack and its engineering justification."
    )
    
    headers_t31 = ["Technology / Library", "Version", "Functional Role in AASF", "Engineering Justification"]
    data_t31 = [
        ["Python", "3.11.9", "Core Programming Language", "Exceptional ecosystem for AI tooling, native type hinting, performance enhancements in 3.11."],
        ["Pydantic", "2.7+", "Data Contracts & Schema Validation", "Data validation and model serialization."],
        ["Cryptography / hashlib", "Standard Lib", "HMAC-SHA256 & Digest Engine", "Cryptographic primitives used for evidence verification and hash-based integrity checks."],
        ["Pytest", "8.0+", "Automated Test Runner", "Supports parameterized fixtures, property testing, and comprehensive regression tracking."],
        ["Ruff", "0.4+", "Linter & Code Formatter", "Ultra-fast Rust-based linter ensuring strict code quality and formatting consistency."],
        ["Mypy", "1.10+", "Static Type Checker", "Enforces strict type safety across all contracts, preventing runtime type-coercion bugs."],
        ["Matplotlib", "3.8+", "Experimental Visualization", "Chart generation for evaluation data."],
    ]
    col_w_t31 = [1.4, 0.8, 1.8, 2.0]
    add_table(doc, headers_t31, data_t31, "Table 3.1", "Technical Dependencies, Cryptographic Standards, and Tooling Stack", col_w_t31)

    # 3.8 Security Requirements and Invariant Catalog
    add_h1(doc, "3.8", "Security Requirements and Invariant Catalog")
    add_p(doc,
        "At the core of AASF lies a catalog of twelve mathematically formalized Security Invariants (INV-01 to INV-12). "
        "These invariants serve as non-negotiable axioms that every execution path must satisfy. Table 3.2 lists the formal catalog."
    )
    
    headers_t32 = ["Invariant ID", "Invariant Name", "Formal Definition & Enforcement Rule"]
    data_t32 = [
        ["INV-01", "Complete Interception", "No tool action executes without passing through the FirewallCore submission pipeline."],
        ["INV-02", "Deterministic State Fold", "State updates follow Phi(S, a, r); given S_0 and history H, S_n is unique, immutable, and deterministic."],
        ["INV-03", "Policy Primacy", "A policy PROHIBIT cannot be overturned by any advisory monitor or model score (P=PROHIBIT => Dec=DENY)."],
        ["INV-04", "Fail-Closed Defaults", "Missing required evidence attributes, schema errors, or monitor timeouts force decision to REVIEW or DENY."],
        ["INV-05", "State Hash Revalidation", "Human review approval is valid iff current state hash matches the state hash recorded at ticket creation."],
        ["INV-06", "Single-Use Tokens", "An execution token T is valid for exactly one tool dispatch; subsequent redemption attempts fail immediately."],
        ["INV-07", "Audit Continuity", "Every state transition and authorization decision is logged in an append-only SHA-256 hash chain."],
        ["INV-08", "Action-Hash Binding", "Execution tokens are cryptographically bound to the hash of the action payload; altered arguments invalidate T."],
        ["INV-09", "Audit Verifiability", "Audit store chains are mathematically verifiable from genesis to leaf; broken links signal tampering."],
        ["INV-10", "Monitor Isolation", "Advisory monitors receive MonitorView projections with sensitive credentials and payload values redacted."],
        ["INV-11", "Session Mutual Exclusion", "Actions within the same session execute under an exclusive session mutex, preventing concurrent race conditions."],
        ["INV-12", "Monotonic Taint Tracking", "Resource classifications (Confidential, Restricted) monotonically elevate session sensitivity and cannot decay."],
    ]
    col_w_t32 = [1.1, 1.6, 3.3]
    add_table(doc, headers_t32, data_t32, "Table 3.2", "Formal Catalog of AASF Core Security Invariants (INV-01 to INV-12)", col_w_t32)

    # 3.9 Constraints and Assumptions
    add_h1(doc, "3.9", "Constraints and Assumptions")
    add_p(doc, "The design and implementation of AASF operate under five documented assumptions and constraints:")
    add_bullet(doc, "Tool dispatch occurs via the designated ControlledExecutor wrapper; direct unmediated OS system calls by the host are prevented by the container environment.", "Assumption A-01 (Interception Authority):")
    add_bullet(doc, "The host operating system kernel and Python runtime process memory are trusted; memory scraping via root physical access is out of scope.", "Assumption A-02 (Process Integrity):")
    add_bullet(doc, "Advisory LLM models are treated as untrusted, stochastic components whose verdicts may be erratic, delayed, or adversarially influenced.", "Assumption A-03 (Advisory Untrustworthiness):")
    add_bullet(doc, "Human reviewers possess the domain competence to inspect flagged review tickets and make correct authorization determinations.", "Assumption A-04 (Reviewer Competence):")
    add_bullet(doc, "Cryptographic primitives (SHA-256, HMAC) are computationally secure against preimage and collision attacks.", "Assumption A-05 (Cryptographic Hardness):")

    add_page_break(doc)
