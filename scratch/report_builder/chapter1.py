"""
AASF Project Report - Chapter 1: Introduction.
Covers:
1.1 Background and Motivation
1.2 Introduction to Autonomous AI Agents
1.3 Security Challenges in Agentic Systems
1.4 Problem Statement
1.5 Motivation and Industry Relevance
1.6 Project Objectives
1.7 Project Scope and System Boundaries
1.8 Proposed Solution: The AASF Framework
1.9 Organization of the Report
"""

from docx import Document
from styles import add_chapter_title, add_h1, add_h2, add_p, add_bullet, add_callout, add_page_break

def add_chapter1(doc: Document):
    add_chapter_title(doc, "CHAPTER 1", "INTRODUCTION")
    
    # 1.1 Background and Motivation
    add_h1(doc, "1.1", "Background and Motivation")
    add_p(doc, 
        "The paradigm of artificial intelligence has transitioned rapidly from passive perception and conversational generation "
        "toward autonomous agency. Modern Large Language Models (LLMs), equipped with structured tool-calling capabilities, "
        "function-execution runtimes, and external memory stores, no longer merely produce static text responses. Instead, they act as "
        "autonomous controllers capable of formulating multi-step reasoning plans, querying enterprise databases, provisioning cloud "
        "infrastructure, orchestrating financial transactions, and communicating across third-party web services. This evolution "
        "promises unprecedented automation across software engineering, customer operations, legal document processing, and enterprise logistics."
    )
    add_p(doc,
        "However, as autonomous AI agents are entrusted with privileged tools and access to sensitive enterprise data stores, they introduce "
        "a critical, unresolved attack surface. Unlike traditional monolithic software systems where execution flows follow deterministic, "
        "hard-coded control paths, LLM-based agents exhibit stochastic, nondeterministic decision-making governed by probabilistic language modeling. "
        "When an agent operates in an open environment, its execution context is continuously polluted by untrusted external data—such as web "
        "pages, incoming emails, customer support tickets, or database query results. Consequently, adversaries can manipulate agent behavior "
        "through indirect prompt injection, jailbreaking, and social engineering without ever directly compromising the underlying host system."
    )
    add_p(doc,
        "Crucially, contemporary cybersecurity perimeter defenses—such as network firewalls, Web Application Firewalls (WAFs), and static "
        "API gateways—are blind to the semantics of multi-step autonomous agency. A tool invocation that appears completely benign in isolation "
        "(such as exporting data to an external cloud bucket) becomes a catastrophic data exfiltration attack if preceded three steps earlier "
        "by an unauthorized read of confidential payroll records. Conventional stateless access control models, such as standard Role-Based "
        "Access Control (RBAC), evaluate permissions purely on a per-action basis and cannot reason over the causal history of an agent's "
        "session. This severe architectural blindspot necessitates a fundamentally new security primitive: an in-process, state-aware runtime firewall."
    )

    # 1.2 Introduction to Autonomous AI Agents
    add_h1(doc, "1.2", "Introduction to Autonomous AI Agents")
    add_p(doc,
        "An autonomous AI agent is defined as a computational entity driven by a foundation model that perceives its environment through "
        "structured observations, maintains internal cognitive state or memory, deliberates over goals via planning algorithms (such as "
        "ReAct, Plan-and-Solve, or Reflexion), and executes actions in the environment via tool invocations. The agent operates in a continuous "
        "perception-action loop formalized as follows:"
    )
    add_bullet(doc, "Perception: The agent ingests user prompts, environment observations, and tool execution return values.", "1. Perception:")
    add_bullet(doc, "Deliberation: The underlying foundation model synthesizes current observations with past reasoning traces to determine the optimal next action.", "2. Deliberation:")
    add_bullet(doc, "Action Formulation: The model emits a structured tool call comprising a tool identifier and strongly typed parameter payload.", "3. Action:")
    add_bullet(doc, "Execution: The runtime environment dispatches the call to the host operating system, database connector, or external API.", "4. Execution:")
    add_p(doc,
        "While this autonomy unlocks tremendous productivity, it creates a dual-use hazard. The agent possesses the capability to modify "
        "real-world state, alter filesystem configurations, and transfer data across network boundaries, while its core reasoning engine "
        "remains inherently susceptible to adversarial semantic steering."
    )

    # 1.3 Security Challenges in Agentic Systems
    add_h1(doc, "1.3", "Security Challenges in Agentic Systems")
    add_p(doc,
        "Securing autonomous agentic workflows involves addressing threats that do not exist in conventional software pipelines. "
        "Through our systematic analysis of the literature and empirical security audits, we identify five principal failure modes:"
    )
    add_bullet(doc, "Adversaries embed malicious instructions within third-party data ingested by the agent (e.g., inside an invoice PDF or webpage). When parsed, the instructions hijack the agent's goal alignment, commanding it to exfiltrate private context or abuse available tools.", "A. Indirect Prompt Injection:")
    add_bullet(doc, "An attacker tricks the agent into acting as an unauthorized intermediary to perform actions that the attacker lacks permissions to execute directly, bypassing boundary firewalls.", "B. Confused Deputy Vulnerabilities:")
    add_bullet(doc, "The hallmark of sophisticated attacks against agents. No single tool call violates policy in isolation. Step 1 reads confidential data (permitted under read policy); Step 2 stages a temporary file; Step 3 transmits data externally. Stateless defenses evaluate each step as legal, failing to detect the exfiltration pipeline.", "C. Multi-Step Context Manipulation:")
    add_bullet(doc, "As an agent executes lengthy workflows, its internal context window accumulates thousands of tokens. Hallucinations, subtle goal misalignments, or attention degradation can cause the agent to wander from its original intent, modifying sensitive resources unintentionally.", "D. Goal Drift and State Degradation:")
    add_bullet(doc, "Existing production solutions frequently default to human-in-the-loop review queues for every sensitive tool call. In high-throughput enterprise pipelines, this floods human operators with hundreds of trivial tickets, inducing severe cognitive fatigue that inevitably leads to erroneous rubber-stamping of malicious requests.", "E. Reviewer Fatigue and Operational Bottlenecks:")

    # 1.4 Problem Statement
    add_h1(doc, "1.4", "Problem Statement")
    add_callout(doc, "FORMAL PROBLEM STATEMENT",
        "Given an autonomous agent session S executing an unbounded sequence of tool invocations {a_1, a_2, ..., a_n} in an "
        "enterprise environment with heterogeneous security classifications, design an in-process security mediation firewall that "
        "provably guarantees complete prevention of multi-step policy violations (Attack Prevention Rate = 1.0) while minimizing "
        "human review burden, maintaining legitimate task success, preserving strict cryptographic non-repudiation, and executing "
        "decision mediation within an operational latency bound of p95 <= 600 ms."
    )

    # 1.5 Motivation and Industry Relevance
    add_h1(doc, "1.5", "Motivation and Industry Relevance")
    add_p(doc,
        "As enterprise organizations adopt AI agent architectures (such as AutoGPT, LangGraph, CrewAI, and OpenAI Assistants), "
        "chief information security officers (CISOs) face an acute compliance and security crisis. Regulatory frameworks such as the "
        "EU AI Act, HIPAA, and ISO/IEC 42001 mandate strict governance, data provenance tracking, and verifiable human oversight for "
        "autonomous decision systems. Deploying autonomous agents without mathematical runtime guardrails creates massive liability, "
        "risking unauthorized data leakage, regulatory fines, and reputational destruction."
    )

    # 1.6 Project Objectives
    add_h1(doc, "1.6", "Project Objectives")
    add_p(doc, "To resolve the aforementioned challenges, this capstone project defines specific, measurable primary and secondary objectives:")
    add_bullet(doc, "Architect and implement an in-process security interception firewall (FirewallCore) capable of capturing all agent tool requests prior to host execution.", "Primary Objective 1 (Interception):")
    add_bullet(doc, "Develop a deterministic, monotonic state-folding engine (Phi) that maintains a tamper-evident, cryptographically hash-chained session state reflecting complete historical resource access.", "Primary Objective 2 (State Awareness):")
    add_bullet(doc, "Formulate a three-valued policy engine (PERMIT, PROHIBIT, REVIEW) combined with a mathematically pure decision combinator (Delta) enforcing twelve strict security invariants (INV-01 to INV-12).", "Primary Objective 3 (Invariant Enforcement):")
    add_bullet(doc, "Design a tiered advisory cascade combining lightweight heuristic classifiers and offline LLM monitors to slash human review overhead without granting models veto or allow authority.", "Primary Objective 4 (Adaptive Cascades):")
    add_bullet(doc, "Implement a cryptographically enforced single-use execution token mechanism (HMAC-SHA256) preventing replay attacks and race conditions.", "Secondary Objective 1 (Token Security):")
    add_bullet(doc, "Empirically evaluate the architecture against pre-registered hypotheses (H1 to H5) across four canonical dataset splits under strict action-history invariance.", "Secondary Objective 2 (Empirical Validation):")

    # 1.7 Project Scope and System Boundaries
    add_h1(doc, "1.7", "Project Scope and System Boundaries")
    add_p(doc, "To ensure rigorous engineering and verifiable evaluation, explicit system boundaries are established:")
    add_bullet(doc, "In-process mediation of agent-to-tool dispatch; deterministic state folding; stateful attribute-based access control; advisory monitor cascades; human review revalidation; single-use token lifecycle; hash-chained audit logging.", "In-Scope (System Core):")
    add_bullet(doc, "Modifying internal LLM transformer weights or model pre-training; hosting external production SaaS databases; hardware-level side-channel attacks; physical tamper resistance of host memory.", "Out-of-Scope (External Environment):")

    # 1.8 Proposed Solution: The AASF Framework
    add_h1(doc, "1.8", "Proposed Solution: The AASF Framework")
    add_p(doc,
        "The Adaptive Agentic Security Firewall (AASF) is engineered as an authoritative mediation boundary positioned directly between the "
        "autonomous agent's reasoning core and the host execution environment. AASF introduces three synchronized pillars of defense:"
    )
    add_bullet(doc, "The Deterministic State Fold (Phi) continually updates the session state vector by folding incoming actions and their confirmed outcomes into an immutable hash chain. Every resource classification, destination zone, and data taint accumulated during the session is permanently tracked.", "1. Stateful Causal History:")
    add_bullet(doc, "The Pure Decision Combinator (Delta) maps the joint state of the policy engine, evidence verifier, and advisory monitors into a definitive trichotomy: ALLOW, DENY, or REVIEW. Crucially, advisory AI monitors are restricted to advisory-only semantics—they can recommend scrutiny, but can never override a deterministic policy prohibition.", "2. Fail-Closed Invariant Combinator:")
    add_bullet(doc, "When human oversight is required, the Review Service generates a cryptographic review ticket bound to the exact state hash. Upon human approval, the state is re-evaluated to prevent time-of-check to time-of-use (TOCTOU) exploits, and a single-use HMAC authorization token is issued directly to the Controlled Executor.", "3. Cryptographic Tokenized Execution:")

    # 1.9 Organization of the Report
    add_h1(doc, "1.9", "Organization of the Report")
    add_p(doc, "The remainder of this report is structured as follows:")
    add_bullet(doc, "Presents a comprehensive review of existing literature, contemporary agent security frameworks, foundational papers, and establishes the comparative matrix and research gaps.", "Chapter 2 (Literature Review):")
    add_bullet(doc, "Details the System Requirement Specification (SRS), formalizing functional (FR-01 to FR-12) and non-functional requirements (NFR-01 to NFR-08), tech stack, and invariant catalog.", "Chapter 3 (System Requirements):")
    add_bullet(doc, "Outlines project planning, WBS, Gantt chart timeline, team ownership matrix, and risk management strategies.", "Chapter 4 (Project Planning):")
    add_bullet(doc, "Provides existing vs. proposed system analysis, feasibility analysis, use case modeling, functional decomposition, and Level 0 DFD.", "Chapter 5 (Project Analysis):")
    add_bullet(doc, "Exposes the architectural blueprint, component design, Level 1 DFD, UML Class, Sequence, and Activity diagrams, state-fold algorithms, and token lifecycle.", "Chapter 6 (Project Design):")
    add_bullet(doc, "Documents implementation specifics across all core modules, code snippets, package structure, and invariant traceability.", "Chapter 7 (Implementation):")
    add_bullet(doc, "Details experimental methodology, benchmark dataset splits, test suite breakdown (415 tests), hypothesis outcomes (H1–H5), latency, ablations, and validity threats.", "Chapter 8 (Result Analysis):")
    add_bullet(doc, "Summarizes project achievements, research and technical contributions, system limitations, future extension roadmaps, and final conclusions.", "Chapter 9 (Conclusion):")
    add_bullet(doc, "Provides full IEEE references, list of research publications (P1–P4), paper abstracts, plagiarism documentation, formal invariant proofs, and cryptographic manifests.", "Back Matter & Appendices:")
    
    add_page_break(doc)
