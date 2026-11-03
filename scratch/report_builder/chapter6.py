"""
AASF Project Report - Chapter 6: Project Design.
Covers:
6.1 Overall System Architecture (Figure 6.1)
6.2 End-to-End Agent Execution Pipeline (Figure 6.2)
6.3 Architectural Design Principles
6.4 Decision Combinator Architecture (Delta) (Figure 6.3)
6.5 State Fold Engine (Phi) and Hash-Chained State Design (Figure 6.4)
6.6 UML Sequence Diagram (Authorization Pipeline) (Figure 6.5)
6.7 Data Flow Diagrams (Level 1 DFD) (Figure 6.6)
6.8 UML Class Diagram (Figure 6.7)
6.9 Security Design: Token Lifecycle and Isolation Views (Figure 6.8, Figure 6.9)
6.10 UML Activity Diagram (Interception and Cascading) (Figure 6.10)
"""

import os
from docx import Document
from styles import add_chapter_title, add_h1, add_h2, add_p, add_bullet, add_table, add_figure, add_callout, add_page_break

def add_chapter6(doc: Document):
    add_chapter_title(doc, "CHAPTER 6", "PROJECT DESIGN")
    
    # 6.1 Overall System Architecture
    add_h1(doc, "6.1", "Overall System Architecture")
    add_p(doc,
        "The architecture of the Adaptive Agentic Security Firewall (AASF) is engineered as an authoritative, modular, and layered "
        "in-process mediation system. It operates between the autonomous agent's reasoning core and the host execution environment. "
        "Figure 6.1 illustrates the comprehensive multi-tiered architecture, highlighting the clear separation between the Interception Layer, "
        "State Engine, Policy Engine, Advisory Cascades, Decision Combinator, Oversight Service, Tokenized Execution Engine, and Cryptographic Audit Store."
    )
    
    # Embed Fig 6.1 Overall AASF Architecture
    arch_path = os.path.join("AASF_FINAL_PROJECT_REPORT", "diagrams", "fig6_1_overall_aasf_architecture.png")
    add_figure(doc, arch_path, "Figure 6.1", "Overall Multi-Tiered AASF System Architecture", width_in=5.8)

    # 6.2 End-to-End Agent Execution Pipeline
    add_h1(doc, "6.2", "End-to-End Agent Execution Pipeline")
    add_p(doc,
        "Figure 6.2 illustrates the end-to-end agent-to-firewall interception and execution pipeline, tracing an intercepted action "
        "through seven discrete mediation stages: Ingress Interception (Stage 1), State Retrieval (Stage 2), Policy Evaluation (Stage 3), "
        "Advisory Monitor Consultation (Stage 4), Pure Decision Combinator Synthesis (Stage 5), Tokenized Execution & State Revalidation (Stage 6), "
        "and Monotonic State Fold & Audit Recording (Stage 7). Terminal paths for ALLOW, DENY, and REVIEW with human revalidation loops are explicitly delineated."
    )
    
    # Embed Fig 6.2 Agent Execution Pipeline
    pipe_path = os.path.join("AASF_FINAL_PROJECT_REPORT", "diagrams", "fig6_2_agent_execution_pipeline.png")
    add_figure(doc, pipe_path, "Figure 6.2", "End-to-End Agent-to-Firewall Interception and Execution Pipeline", width_in=5.8)

    # 6.3 Architectural Design Principles
    add_h1(doc, "6.3", "Architectural Design Principles")
    add_p(doc, "AASF’s architectural blueprint is governed by four immutable engineering principles:")
    add_bullet(doc, "The firewall is an inescapable reference monitor. No execution handle exists in the agent's process space that can invoke tools without traversing FirewallCore (INV-01).", "1. Complete Mediation:")
    add_bullet(doc, "Security-relevant attributes, such as data sensitivity classifications and network zone bindings, monotonically accumulate within the session state and cannot be erased or downgraded by subsequent unprivileged actions (INV-12).", "2. Monotonic State Accumulation:")
    add_bullet(doc, "Every component boundary enforces a strict information barrier. Advisory models and human reviewers receive projection views with sensitive values redacted, preventing secondary data leakage (INV-10).", "3. Principle of Least Privilege & Isolation:")
    add_bullet(doc, "In the presence of any ambiguity—whether missing evidence tokens, unparseable payloads, or model execution timeouts—the system defaults to a secure non-executing state (REVIEW or DENY) (INV-04).", "4. Fail-Closed Default Stance:")

    # 6.4 Decision Combinator Architecture (Delta)
    add_h1(doc, "6.4", "Decision Combinator Architecture (Delta)")
    add_p(doc,
        "The Decision Combinator is the central arbiter of AASF. It evaluates inputs across a three-valued lattice: "
        "Policy Verdict P in {PERMIT, PROHIBIT, REVIEW}, Evidence Status E in {VALID, INVALID, MISSING}, and Monitor Verdict "
        "M in {BENIGN, SUSPICIOUS, MALICIOUS, NOT_CONSULTED}. Figure 6.3 details the combinator flowchart, verifying how strict "
        "invariants guarantee that advisory models can never overturn a policy prohibition (INV-03, INV-04)."
    )
    
    # Embed Fig 6.3 Decision Combinator Flowchart
    dc_path = os.path.join("AASF_FINAL_PROJECT_REPORT", "diagrams", "fig6_3_decision_combinator_flowchart.png")
    add_figure(doc, dc_path, "Figure 6.3", "Decision Combinator Flowchart and Strict Security Invariant Evaluation", width_in=5.8)

    # 6.5 State Fold Engine (Phi) and Hash-Chained State Design
    add_h1(doc, "6.5", "State Fold Engine (Phi) and Hash-Chained State Design")
    add_p(doc,
        "The state-folding operator Phi mathematically formalizes how session history accumulates. Given the state at step n-1, "
        "an action a_n, and confirmed result r_n, the state transition is defined as: S_n = Phi(S_{n-1}, a_n, r_n). "
        "Figure 6.4 illustrates the hash-chained state architecture, showing how each state transition produces an immutable, "
        "cryptographically linked state vector anchored by SHA-256 state-head hashes (INV-02, INV-07, INV-12)."
    )
    
    # Embed Fig 6.4 Hash-Chained State Architecture
    state_path = os.path.join("AASF_FINAL_PROJECT_REPORT", "diagrams", "fig6_4_hash_chained_state_architecture.png")
    add_figure(doc, state_path, "Figure 6.4", "Monotonic State Fold (Phi) and Hash-Chained Cryptographic Architecture", width_in=5.8)

    # 6.6 UML Sequence Diagram (Authorization Pipeline)
    add_h1(doc, "6.6", "UML Sequence Diagram (Authorization Pipeline)")
    add_p(doc,
        "Figure 6.5 illustrates the end-to-end authorization sequence for an action following the complete evaluation path. "
        "It details the exact synchronous interactions between the Agent, FirewallCore, PolicyEngine, AdvisoryMonitor, "
        "DecisionCombinator, TokenStore, ControlledExecutor, and AuditStore, verifying in-process mediation where the agent never accesses tokens directly."
    )
    
    # Embed Fig 6.5 Sequence Diagram
    seq_path = os.path.join("AASF_FINAL_PROJECT_REPORT", "diagrams", "fig6_5_uml_sequence_diagram.png")
    add_figure(doc, seq_path, "Figure 6.5", "UML Sequence Diagram: Complete Action Request Authorization Lifecycle", width_in=5.8)

    # 6.7 Data Flow Diagrams (Level 1 DFD)
    add_h1(doc, "6.7", "Data Flow Diagrams (Level 1 DFD)")
    add_p(doc,
        "Figure 6.6 provides the detailed Level 1 Data Flow Diagram (DFD Level 1). It traces the transformation of an incoming "
        "ActionRequest across internal processes, data stores (Session Store, Policy Store, Token Store, Audit Store), and decision sinks."
    )
    
    # Embed Fig 6.10 DFD Level 1
    dfd1_path = os.path.join("AASF_FINAL_PROJECT_REPORT", "diagrams", "fig6_10_dfd_level_1.png")
    add_figure(doc, dfd1_path, "Figure 6.6", "Detailed Level 1 Data Flow Diagram (DFD Level 1) for Core Subsystems", width_in=5.8)

    # 6.8 UML Class Diagram
    add_h1(doc, "6.8", "UML Class Diagram")
    add_p(doc,
        "The object-oriented structure of AASF is modeled using strict Pydantic v2 data models and pure service classes. "
        "Figure 6.7 presents the UML Class Diagram displaying core classes (`FirewallCore`, `SessionState`, `CanonicalAction`, "
        "`PolicyEngine`, `DecisionCombinator`, `TokenStore`, `AuditStore`), their attributes, methods, and structural relationships."
    )
    
    # Embed Fig 6.7 UML Class Diagram
    class_path = os.path.join("AASF_FINAL_PROJECT_REPORT", "diagrams", "fig6_7_uml_class_diagram.png")
    add_figure(doc, class_path, "Figure 6.7", "UML Class Diagram of FirewallCore, StateEngine, and Decision Modules", width_in=5.8)

    # 6.9 Security Design: Token Lifecycle and Isolation Views
    add_h1(doc, "6.9", "Security Design: Token Lifecycle and Isolation Views")
    add_p(doc,
        "To satisfy INV-06 and INV-10, AASF enforces strict token lifecycle transitions and information isolation barriers. "
        "Figure 6.8 illustrates the MonitorView isolation mechanism, showing how raw session data is projected into sanitized "
        "views before advisory monitor consultation. Figure 6.9 depicts the single-use token lifecycle: tokens transition from "
        "ISSUED -> CONSUMED, with expired, mismatched, or replayed tokens immediately rejected."
    )
    
    # Embed Fig 6.8 MonitorView Isolation
    mv_path = os.path.join("AASF_FINAL_PROJECT_REPORT", "diagrams", "fig6_8_monitorview_isolation.png")
    add_figure(doc, mv_path, "Figure 6.8", "MonitorView Information Isolation Barrier (INV-10 Redaction Enforcement)", width_in=5.8)

    # Embed Fig 6.9 Token Lifecycle
    tok_path = os.path.join("AASF_FINAL_PROJECT_REPORT", "diagrams", "fig6_9_token_lifecycle.png")
    add_figure(doc, tok_path, "Figure 6.9", "Single-Use Cryptographic Execution Token Lifecycle and Transition Model", width_in=5.8)

    # 6.10 UML Activity Diagram (Interception and Cascading)
    add_h1(doc, "6.10", "UML Activity Diagram (Interception and Cascading)")
    add_p(doc,
        "Figure 6.10 illustrates the operational activity flow, demonstrating the branching logic between fast-path authorization, "
        "tiered advisory cascade invocation, human oversight suspension, and controlled tool dispatch."
    )
    
    # Embed Fig 6.11 UML Activity Diagram
    act_path = os.path.join("AASF_FINAL_PROJECT_REPORT", "diagrams", "fig6_11_uml_activity_diagram.png")
    add_figure(doc, act_path, "Figure 6.10", "UML Activity Diagram for Dynamic Advisory Cascades and Fallback Routing", width_in=5.8)

    add_page_break(doc)


