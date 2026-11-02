"""
AASF Project Report - Chapter 4: Plan of Project.
Covers:
4.1 Project Planning Overview
4.2 Development Methodology (Test-Driven Invariant Engineering)
4.3 Research Methodology and Protocol Pre-registration
4.4 Project Phases and Milestones
4.5 Work Breakdown Structure (WBS)
4.6 Timeline and Gantt Chart
4.7 Team Ownership and Responsibility Matrix
4.8 Risk Management and Mitigation Strategies
"""

import os
from docx import Document
from styles import add_chapter_title, add_h1, add_h2, add_p, add_bullet, add_table, add_figure, add_callout, add_page_break

def add_chapter4(doc: Document):
    add_chapter_title(doc, "CHAPTER 4", "PLAN OF PROJECT")
    
    # 4.1 Project Planning Overview
    add_h1(doc, "4.1", "Project Planning Overview")
    add_p(doc,
        "Engineering an enterprise-grade runtime security firewall for autonomous agent workflows requires rigorous planning, "
        "disciplined milestone management, and formal separation between software development and scientific evaluation. "
        "Given the mission-critical nature of cybersecurity systems, ad-hoc development methodologies risk introducing subtle "
        "race conditions, unhandled exception paths, or unverifiable empirical claims. This chapter details the project's "
        "management framework, development philosophy, research preregistration, Work Breakdown Structure (WBS), Gantt chart timeline, "
        "team ownership matrix, and risk mitigation strategies."
    )

    # 4.2 Development Methodology (Test-Driven Invariant Engineering)
    add_h1(doc, "4.2", "Development Methodology (Test-Driven Invariant Engineering)")
    add_p(doc,
        "The project adopted Test-Driven Invariant Engineering (TDIE), an enhanced variant of Test-Driven Development (TDD) tailored "
        "specifically for formal security systems. In TDIE, development proceeds through four iterative cycles:"
    )
    add_bullet(doc, "Before writing any component logic, the mathematical security invariant governing the module (e.g., INV-06 Single-Use Tokens) is formalized into executable unit and property-based test cases.", "1. Invariant Formalization & Test Authoring:")
    add_bullet(doc, "The test suite is executed, verifying that unmediated execution fails as expected (red phase).", "2. Failure Verification:")
    add_bullet(doc, "The minimal authoritative component logic is implemented to satisfy the invariant, ensuring fail-closed default branches on all exception paths (green phase).", "3. Authoritative Implementation:")
    add_bullet(doc, "The code is refactored for latency optimization and strict typing under Mypy and Ruff, accompanied by regression tests to ensure no invariant drift (refactor phase).", "4. Optimization & Regression Hardening:")

    # 4.3 Research Methodology and Protocol Pre-registration
    add_h1(doc, "4.3", "Research Methodology and Protocol Pre-registration")
    add_p(doc,
        "To guarantee absolute scientific integrity and prevent post-hoc hypothesizing (p-hacking), the project implemented formal "
        "experiment pre-registration. Prior to evaluating the firewall against the test splits, the research team authored and cryptographically "
        "locked the experimental protocol in docs/prereg/PREREG-001.md, generating a SHA-256 commitment digest:"
    )
    add_callout(doc, "PRE-REGISTERED BENCHMARK COMMITMENT (PREREG-001)",
        "Protocol Digest: 88038e76161686bd3cc4fd0a12757e9d4264f406a7d5399a9ba6bff92ee37fd5\n"
        "Benchmark Commitments: Sealed across DEV (N=32), CAL (N=8), TEST-IN (N=8), and TEST-NOVEL (N=4).\n"
        "Action-D Invariance: Matched attack-benign twin pairs share mathematically identical final action vectors a_D."
    )
    add_p(doc,
        "This methodology guarantees that test splits remained completely quarantined from the engineering phase, preventing label leakage "
        "or over-fitting during algorithm development."
    )

    # 4.4 Project Phases and Milestones
    add_h1(doc, "4.4", "Project Phases and Milestones")
    add_p(doc, "The project was executed across nine structured phases spanning the 2026–2027 academic year:")
    add_bullet(doc, "Systematic literature survey, formal threat modeling (01_THREAT_MODEL.md), requirement elicitation, and mathematical formalization of invariants INV-01 to INV-12.", "Phase 1: Problem Definition & Threat Modeling (Months 1–2):")
    add_bullet(doc, "Definition of immutable Pydantic v2 data contracts, schema snapshots, and foundational HMAC/SHA-256 cryptographic utilities.", "Phase 2: Contract Specifications & Cryptographic Primitives (Month 3):")
    add_bullet(doc, "Implementation of FirewallCore in-process interception, thread-safe session locking, and ControlledExecutor abstraction.", "Phase 3: Core Runtime Interception Architecture (Month 4):")
    add_bullet(doc, "Development of the deterministic state engine Phi, three-valued PolicyEngine, and pure DecisionCombinator Delta.", "Phase 4: State Engine & Policy Evaluator (Month 5):")
    add_bullet(doc, "Construction of ReviewService, cryptographic ticket lifecycle, state revalidation logic, and single-use TokenStore.", "Phase 5: Human Oversight & Token Management (Month 6):")
    add_bullet(doc, "Implementation of pluggable heuristic cascades, SafeMonitorWrapper, and isolated MonitorView projections.", "Phase 6: Tiered Advisory Monitor Cascades (Month 7):")
    add_bullet(doc, "Authoring of the deterministic dataset generator, action-history twin synthesis, and protocol pre-registration locking.", "Phase 7: Benchmark Dataset & Pre-Registration (Month 8):")
    add_bullet(doc, "Execution of 8 experimental arms across DEV, CAL, TEST-IN, and TEST-NOVEL; ablation studies and latency profiling.", "Phase 8: Empirical Evaluation & Ablation Studies (Month 9):")
    add_bullet(doc, "Compilation of academic publications (P1–P4), capstone dissertation, engineering audit reports, and artifact delivery.", "Phase 9: Documentation, Dissertation & Code Finalization (Month 10):")

    # 4.5 Work Breakdown Structure (WBS)
    add_h1(doc, "4.5", "Work Breakdown Structure (WBS)")
    add_p(doc,
        "Table 4.1 delineates the Work Breakdown Structure, detailing the discrete work packages, deliverables, and completion milestones."
    )
    
    headers_t41 = ["WBS Code", "Work Package Description", "Primary Deliverables", "Target Milestone"]
    data_t41 = [
        ["1.0", "System Architecture & Threat Modeling", "Threat Model, SRS, Invariant Formalization", "Milestone M1 (Completed)"],
        ["2.0", "Core Interception & Runtime Engine", "FirewallCore, Session Locks, Interception Hook", "Milestone M2 (Completed)"],
        ["3.0", "State Folding & Policy Evaluation", "StateEngine (Phi), PolicyEngine, Rule Lattice", "Milestone M3 (Completed)"],
        ["4.0", "Decision Combinator & Security Invariants", "Pure Decider Delta, Fail-Closed Evaluator", "Milestone M4 (Completed)"],
        ["5.0", "Oversight Platform & Token Management", "ReviewService, TokenStore, ControlledExecutor", "Milestone M5 (Completed)"],
        ["6.0", "Advisory Cascades & Information Barrier", "B4 CascadeAdapter, SafeMonitorWrapper, Redaction", "Milestone M6 (Completed)"],
        ["7.0", "Benchmark Generation & Manifests", "Deterministic Dataset Generator, Sealed Manifests", "Milestone M7 (Completed)"],
        ["8.0", "Evaluation, Ablations & Benchmarking", "Hypothesis Verification (H1-H5), Latency Analysis", "Milestone M8 (Completed)"],
        ["9.0", "Reporting & Artifact Verification", "Comprehensive Report, Traceability Matrix, CI Audit", "Milestone M9 (Completed)"],
    ]
    col_w_t41 = [1.0, 2.0, 2.0, 1.0]
    add_table(doc, headers_t41, data_t41, "Table 4.1", "Work Breakdown Structure (WBS) and Phase-Wise Deliverables", col_w_t41)

    # 4.6 Timeline and Gantt Chart
    add_h1(doc, "4.6", "Timeline and Gantt Chart")
    add_p(doc,
        "The project execution timeline followed a structured 10-month schedule. Figure 4.1 illustrates the comprehensive "
        "Gantt chart mapping work packages, dependencies, and delivery milestones across the academic year."
    )
    
    # Embed Fig 4.1 Gantt Chart
    gantt_path = os.path.join("AASF_FINAL_PROJECT_REPORT", "diagrams", "fig4_1_project_gantt_chart.png")
    add_figure(doc, gantt_path, "Figure 4.1", "Project Work Breakdown Structure and Timeline Gantt Chart (2026–2027)", width_in=5.8)

    # 4.7 Team Ownership and Responsibility Matrix
    add_h1(doc, "4.7", "Team Ownership and Responsibility Matrix")
    add_p(doc,
        "The capstone engineering team consisted of four undergraduate researchers, each maintaining primary architectural "
        "and technical ownership over a specialized subsystem of AASF. Table 4.2 presents the team ownership matrix."
    )
    
    headers_t42 = ["Student Name", "Roll Number", "Designated Subsystem", "Key Technical Ownership & Deliverables"]
    data_t42 = [
        ["Shrishti Singh", "F232984", "AI/ML & AI Risk/Threat Detection", "Advisory monitor cascades (B4/B5/P1), prompt injection modeling, action-history manipulation analysis, model clients, benchmark hypothesis H1/H2 validation."],
        ["Snehal Jagtap", "F232951", "Full-Stack & Human Oversight Platform", "ReviewService ticketing, dynamic review queue optimization, reviewer UI/CLI views, state revalidation (INV-05), reviewer fatigue mitigation models (P4)."],
        ["Karishma Thakur", "G242936", "Permission & Dynamic Policy Engine", "Three-valued PolicyEngine (PERMIT/PROHIBIT/REVIEW), stateful ABAC lattice, monotonic taint tracking (INV-12), rule evaluation algorithms (P2)."],
        ["Akshat Kasurde", "F233339", "Runtime Firewall & Agent Execution", "FirewallCore in-process interception, session concurrency locks (INV-11), ControlledExecutor, single-use TokenStore (INV-06), fast-path routing (P3)."],
    ]
    col_w_t42 = [1.2, 0.9, 1.7, 2.2]
    add_table(doc, headers_t42, data_t42, "Table 4.2", "Team Responsibilities and Engineering Ownership Matrix", col_w_t42)

    # 4.8 Risk Management and Mitigation Strategies
    add_h1(doc, "4.8", "Risk Management and Mitigation Strategies")
    add_p(doc,
        "To prevent technical roadblocks or delivery slippages, a proactive risk management assessment was conducted. Table 4.3 "
        "identifies the primary risks, evaluated probability and impact, and the corresponding mitigation protocols implemented in AASF."
    )
    
    headers_t43 = ["Risk Description", "Category", "Probability", "Impact", "Enforced Mitigation Strategy in AASF"]
    data_t43 = [
        ["Advisory LLM latency violates 600 ms SLA", "Performance", "Medium", "High", "Implemented tiered cascade: 90%+ benign requests resolved via sub-ms heuristic fast-path."],
        ["State drift between review approval and execution (TOCTOU)", "Security", "High", "Critical", "Enforced INV-05: State hash recorded in ticket must match current state head hash at redemption."],
        ["Duplicate token redemption in concurrent workloads", "Security", "Medium", "Critical", "Enforced INV-06: Atomic, thread-safe token consumption using threading locks and TokenStore."],
        ["Test split leakage into training/development", "Methodological", "Low", "High", "Strict cryptographic separation: test commitments sealed in SHA-256 manifests; automated CI leakage checks."],
        ["Reviewer fatigue causing accidental rubber-stamping", "Operational", "High", "Medium", "Adaptive oversight filtering: advisory cascades eliminate 75%+ of redundant review tickets."],
    ]
    col_w_t43 = [1.5, 0.9, 0.7, 0.7, 2.2]
    add_table(doc, headers_t43, data_t43, "Table 4.3", "Project Risk Assessment, Probability, Impact, and Mitigation Strategies", col_w_t43)

    add_page_break(doc)
