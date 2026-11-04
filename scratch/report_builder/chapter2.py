"""
AASF Project Report - Chapter 2: Literature Review.
Covers:
2.1 Introduction
2.2 Existing Security Approaches
2.3 Review of Relevant Research Papers
2.4 Comparative Analysis Matrix
2.5 Research Gaps in Contemporary Frameworks
2.6 Research Contributions of AASF
2.7 Summary
"""

from docx import Document
from styles import add_chapter_title, add_h1, add_h2, add_p, add_bullet, add_table, add_callout, add_page_break

def add_chapter2(doc: Document):
    add_chapter_title(doc, "CHAPTER 2", "LITERATURE REVIEW")
    
    # 2.1 Introduction
    add_h1(doc, "2.1", "Introduction")
    add_p(doc,
        "The emergence of autonomous agentic systems has stimulated intense cross-disciplinary research spanning artificial intelligence, "
        "programming language theory, and computer systems security. While foundation models have achieved remarkable conversational fluency, "
        "their integration with external execution environments has outpaced the development of formal security guarantees. This chapter "
        "provides a comprehensive survey of contemporary literature, critically analyzes existing defensive paradigms, evaluates foundational "
        "formal access control models, establishes a comparative analysis matrix, and identifies the core research gaps addressed by the "
        "Adaptive Agentic Security Firewall (AASF)."
    )

    # 2.2 Existing Security Approaches
    add_h1(doc, "2.2", "Existing Security Approaches")
    add_p(doc, "Current industry and academic efforts to secure LLM-based agent systems can be categorized into four distinct paradigms:")
    
    add_bullet(doc, 
        "Developers attempt to constrain agent behavior by embedding natural language instructions in the system prompt "
        "(e.g., 'Never export confidential files to external servers'). While simple to deploy, research has repeatedly demonstrated that "
        "natural language prompts are inherently soft boundaries. Adversarial techniques such as recursive prompt injection, persona manipulation, "
        "and character encoding bypasses reliably circumvent prompt-level constraints.", 
        "1. System Prompt Hardening and Pre-Prompting:"
    )
    add_bullet(doc, 
        "Frameworks such as NeMo Guardrails, Guardrails AI, and Llama Guard inspect raw textual model outputs using regular expressions, "
        "keyword blocklists, or secondary text classifiers. While effective at blocking overt toxicity or prohibited keywords, output guards "
        "are semantically unaware of tool execution state, cannot reason over structured JSON parameter schemas, and fail to recognize subtle "
        "parameter tampering.", 
        "2. Output Filters and Regex Guardrails:"
    )
    add_bullet(doc, 
        "Enterprise architectures frequently wrap agent tool calls in standard API gateways (e.g., Kong, Apigee) enforcing OAuth2 scopes or "
        "Role-Based Access Control (RBAC). In this model, if an agent has permission to call 'execute_export', every call to that endpoint is "
        "permitted. Stateless gateways evaluate each request in total isolation, remaining blind to whether the data being exported was "
        "acquired through an earlier privileged read operation.", 
        "3. Stateless API Gateways and Perimeter RBAC:"
    )
    add_bullet(doc, 
        "Systems route every sensitive tool invocation to a human administrator for manual approval. While nominally safe, this paradigm "
        "creates extreme operational friction. In autonomous multi-agent environments generating thousands of daily transactions, human "
        "operators suffer from cognitive overload, resulting in approval delays and high rubber-stamping rates that negate security benefits.", 
        "4. Unconstrained Human-in-the-Loop Review:"
    )

    # 2.3 Review of Relevant Research Papers
    add_h1(doc, "2.3", "Review of Relevant Research Papers")
    add_p(doc, "Our research builds upon and extends several milestone contributions in the field of autonomous agent security and execution monitoring:")

    add_bullet(doc,
        "ToolSafe (ACL 2026) introduced fine-grained parameter validation for tool-augmented language models. The authors proposed a static "
        "schema validator that verifies parameter types and domain constraints before tool dispatch. However, ToolSafe operates purely at the "
        "single-step level; it maintains no causal memory of prior tool executions and cannot detect multi-step exfiltration attacks.",
        "ToolSafe: Schema-Enforced Tool Execution (ACL 2026):"
    )
    add_bullet(doc,
        "StepGuard (EMNLP 2026 / arXiv:2608.24777) explored runtime step verification by prompting an auxiliary LLM judge after every agent reasoning step. "
        "While StepGuard demonstrated improved attack detection on synthetic benchmarks, the authors acknowledged severe operational limitations: "
        "invoking a secondary LLM on every step inflated end-to-end execution latency by 300% to 800% and introduced stochastic judge errors, "
        "frequently failing closed on legitimate developer tasks.",
        "StepGuard: LLM-as-a-Judge Runtime Supervision (EMNLP 2026):"
    )
    add_bullet(doc,
        "TraceSafe (COLM 2026 / arXiv:2604.07223) recognized the necessity of multi-step trace auditing, proposing an offline log analysis engine "
        "that constructs provenance graphs of agent execution traces. While TraceSafe provides valuable post-incident forensic capabilities, "
        "it operates strictly post-hoc. It offers no real-time inline interception or pre-execution prevention mechanisms.",
        "TraceSafe: Post-Hoc Multi-Step Trace Auditing (COLM 2026):"
    )
    add_bullet(doc,
        "HarnessRisk (arXiv:2608.17597) formalized an evaluation harness for measuring risk in agentic tool-use environments. The authors defined "
        "standard metrics including Attack Prevention Rate (APR) and Legitimate Task Success (LTS), demonstrating that unconstrained agents "
        "experience a 68% attack success rate when exposed to adversarial prompt injections in multi-step scenarios.",
        "HarnessRisk: Benchmarking Tool-Use Risk in Agentic Workflows (2026):"
    )
    add_bullet(doc,
        "In his seminal work on security automata, Fred B. Schneider formalized the boundaries of execution monitors (EM), proving that "
        "enforceable security policies correspond precisely to safety properties that can be determined by observing execution prefixes. "
        "AASF directly applies Schneider's security automata foundation to agentic tool dispatch, ensuring that our state-folding mechanism "
        "maintains sound prefix properties over execution histories.",
        "Schneider’s Formal Security Automata and Execution Monitors (ACM CSUR 2000):"
    )
    
    add_p(doc,
        "Furthermore, this project synthesizes and operationalizes four foundational research investigations conducted within our research cohort:"
    )
    add_bullet(doc,
        "Singh, Kumar, and Haque, 'State vs. Context: Evaluating LLM Runtime Monitors under Action-History Manipulation' (docs/research/shrishti). "
        "This research investigated monitor performance on multi-step history manipulation. The current benchmark reports split-specific "
        "Youden's J values for B3, B4, B6, and P1 in Chapter 8.",
        "[P1] State-History Monitoring Foundations:"
    )
    add_bullet(doc,
        "Thakur, Kumar, and Haque, 'Self-Adapting Attribute-Based Access Control (SA-ABAC) for Multi-Agent Collaboration' (docs/research/karishma). "
        "This study formalized the dynamic, attribute-based policy lattice and state taint propagation algorithms adopted in AASF's PolicyEngine.",
        "[P2] Dynamic Policy Lattice and Attribute Adaptation:"
    )
    add_bullet(doc,
        "Kasurde, Kumar, and Haque, 'Adaptive Security-Check Depth: A Tiered Rejection Cascade for Latency-Constrained Interception' (docs/research/akshat). "
        "This research describes tiered fast-path and cascade-path heuristic filters. No provider-latency or 90% fast-path result is claimed here.",
        "[P3] Tiered Advisory Cascades and Fast-Path Routing:"
    )
    add_bullet(doc,
        "Jagtap, Kumar, and Haque, 'Workload-Aware Adaptive Dynamic Oversight for Human-Agent Systems' (docs/research/snehal). "
        "This work discusses workload-aware human review. The current benchmark reports review-rate changes by arm and split in Chapter 8.",
        "[P4] Dynamic Human Oversight and Reviewer Fatigue Optimization:"
    )

    # 2.4 Comparative Analysis Matrix
    add_h1(doc, "2.4", "Comparative Analysis Matrix")
    add_p(doc,
        "To clearly position AASF against contemporary research and industrial paradigms, Table 2.1 provides a structured "
        "comparative evaluation across seven critical security and architectural dimensions."
    )
    
    headers_t21 = ["Security Dimension", "Conventional RBAC", "Prompt Guardrails", "ToolSafe (2026)", "StepGuard (2026)", "TraceSafe (2026)", "Proposed AASF"]
    data_t21 = [
        ["Interception Layer", "Network / Gateway", "Application Input", "Tool Interface", "Agent Output", "Post-Hoc Logs", "In-Process Kernel"],
        ["State Awareness", "Stateless (Per-Op)", "Stateless (Context)", "Stateless (Single)", "Windowed Context", "Full Trace (Post)", "Deterministic State Fold"],
        ["Multi-Step Exfiltration Defense", "Vulnerable (Blind)", "Vulnerable (Soft)", "Vulnerable (Blind)", "Partial (Heuristic)", "Detection Only", "M-APR = 1.0 on evaluated TEST-IN and TEST-NOVEL traces (B6/P1)"],
        ["Human Review Integration", "Manual Gates", "None", "None", "All High-Risk", "Post-Incident", "Adaptive Dynamic Cascade"],
        ["Execution Authorization", "API Bearer Token", "None", "Direct Call", "Direct Call", "None (Audit)", "Single-use action/state-bound authorization token"],
        ["Audit Tamper-Resistance", "Plain Database", "Application Logs", "None", "Plain Logs", "Signed Traces", "SHA-256 Hash Chaining"],
    ]
    col_w_t21 = [1.3, 0.8, 0.8, 0.8, 0.8, 0.8, 1.2]
    add_table(doc, headers_t21, data_t21, "Table 2.1", "Comparative Analysis Matrix of Agent Security Frameworks vs. Proposed AASF", col_w_t21)

    # 2.5 Research Gaps in Contemporary Frameworks
    add_h1(doc, "2.5", "Research Gaps in Contemporary Frameworks")
    add_p(doc, "Our critical review of contemporary literature highlights four foundational research gaps:")
    add_bullet(doc, 
        "Existing defenses either inspect the isolated action or pass the raw context window to an auxiliary model. No prior system "
        "provides a deterministic mathematical state-folding operator Phi(S, a, r) that monotonically tracks sensitive data access, "
        "destination zones, and privilege classifications into a compact, tamper-evident vector.",
        "Gap 1: Absence of Deterministic State-History Folding:"
    )
    add_bullet(doc, 
        "Many emerging proposals employ LLMs as autonomous security judges. However, when an LLM judge makes an error, it can erroneously "
        "allow a catastrophic action. Literature lacks a formal combinator framework where secondary AI models are strictly constrained "
        "to advisory-only semantics within a three-valued policy lattice.",
        "Gap 2: Unsafe Authority Delegation to Non-Deterministic Judges:"
    )
    add_bullet(doc, 
        "Existing frameworks verify permissions but dispatch tool calls through standard execution handles. If a race condition occurs, "
        "or an attacker replays a previously approved payload, the execution engine cannot verify whether authorization was already redeemed.",
        "Gap 3: Vulnerability to Token Replay and TOCTOU Exploits:"
    )
    add_bullet(doc, 
        "Prior benchmarks frequently evaluate agents on single-step synthetic queries or confound history manipulation with action-type "
        "differences, preventing rigorous evaluation of whether defenses genuinely detect multi-step causal manipulation.",
        "Gap 4: Lack of Action-History Invariant Benchmarks:"
    )

    # 2.6 Research Contributions of AASF
    add_h1(doc, "2.6", "Research Contributions of AASF")
    add_p(doc, "To resolve these identified gaps, the Adaptive Agentic Security Firewall delivers five explicit contributions:")
    add_bullet(doc, "Implemented a deterministic state-folding engine that tracks modeled session state across the multi-step traces exercised by the repository.", "1. Deterministic State Engine:")
    add_bullet(doc, "Implemented a decision combinator that applies the documented policy precedence and fail-closed rules, with advisory monitors restricted to advice.", "2. Invariant Decision Combinator:")
    add_bullet(doc, "Implemented a single-use authorization-token pipeline with action binding, expiry, and replay checks. HMAC-SHA256 is used separately by the evidence verifier.", "3. Single-Use Token Architecture:")
    add_bullet(doc, "The benchmark summary reports B6 review-rate reductions relative to B3 of 75% on TEST-IN (0.3333 to 0.0833) and 100% on TEST-NOVEL (0.2500 to 0.0000).", "4. Adaptive Oversight Evaluation:")
    add_bullet(doc, "Evaluated the four dataset splits DEV, CAL, TEST-IN, and TEST-NOVEL under the preregistered protocol. Results are reported by split and arm.", "5. Empirical Benchmark:")

    # 2.7 Summary
    add_h1(doc, "2.7", "Summary")
    add_p(doc,
        "Contemporary literature reveals an urgent, unaddressed gap between stateless perimeter controls and non-deterministic LLM judges. "
        "AASF combines in-process action mediation, stateful policy evaluation, advisory monitor consultation, and controlled execution. "
        "The benchmark results and their limits are reported by arm and split in Chapter 8."
    )
    
    add_page_break(doc)
