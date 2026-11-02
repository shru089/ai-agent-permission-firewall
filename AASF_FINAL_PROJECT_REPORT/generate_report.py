from docx import Document
from docx.shared import Pt, Inches, RGBColor, Cm
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_LINE_SPACING
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.section import WD_SECTION
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

doc = Document()

# ---------------- Base styles ----------------
normal = doc.styles["Normal"]
normal.font.name = "Times New Roman"
normal.font.size = Pt(12)
normal.paragraph_format.space_after = Pt(6)
normal.paragraph_format.line_spacing = 1.5

# Page margins
for section in doc.sections:
    section.top_margin = Inches(1)
    section.bottom_margin = Inches(1)
    section.left_margin = Inches(1)
    section.right_margin = Inches(1)

NAVY = RGBColor(0x1F, 0x3A, 0x5F)
BLACK = RGBColor(0x00, 0x00, 0x00)

def set_cell_bg(cell, color_hex):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), color_hex)
    tcPr.append(shd)

def add_heading(text, level=1):
    p = doc.add_paragraph()
    if level == 1:
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = p.add_run(text)
        run.bold = True
        run.font.size = Pt(16)
        run.font.color.rgb = NAVY
        p.paragraph_format.space_before = Pt(18)
        p.paragraph_format.space_after = Pt(10)
    elif level == 2:
        p.alignment = WD_ALIGN_PARAGRAPH.LEFT
        run = p.add_run(text)
        run.bold = True
        run.font.size = Pt(13)
        run.font.color.rgb = NAVY
        p.paragraph_format.space_before = Pt(14)
        p.paragraph_format.space_after = Pt(6)
    elif level == 3:
        run = p.add_run(text)
        run.bold = True
        run.font.size = Pt(12)
        p.paragraph_format.space_before = Pt(10)
        p.paragraph_format.space_after = Pt(4)
    return p

def add_body(text, bold=False, italic=False, align=WD_ALIGN_PARAGRAPH.JUSTIFY, size=12, space_after=6):
    p = doc.add_paragraph()
    p.alignment = align
    run = p.add_run(text)
    run.bold = bold
    run.italic = italic
    run.font.size = Pt(size)
    p.paragraph_format.space_after = Pt(space_after)
    return p

def add_bullet(text, level=0):
    p = doc.add_paragraph(style="List Bullet" if level == 0 else "List Bullet 2")
    p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    run = p.add_run(text)
    run.font.size = Pt(12)
    p.paragraph_format.space_after = Pt(3)
    return p

def add_numbered(text):
    p = doc.add_paragraph(style="List Number")
    p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    run = p.add_run(text)
    run.font.size = Pt(12)
    p.paragraph_format.space_after = Pt(3)
    return p

def add_caption(text):
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run(text)
    run.bold = True
    run.font.size = Pt(10)
    run.italic = True
    run.font.color.rgb = NAVY
    p.paragraph_format.space_before = Pt(2)
    p.paragraph_format.space_after = Pt(10)
    return p

def add_page_break():
    doc.add_page_break()

def add_table(headers, rows, col_widths=None, header_bg="1F3A5F", font_size=9):
    table = doc.add_table(rows=1 + len(rows), cols=len(headers))
    table.style = "Table Grid"
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    # Header
    for j, h in enumerate(headers):
        cell = table.rows[0].cells[j]
        cell.text = ""
        p = cell.paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = p.add_run(h)
        run.bold = True
        run.font.size = Pt(font_size)
        run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
        set_cell_bg(cell, header_bg)
    # Body
    for i, row in enumerate(rows):
        for j, val in enumerate(row):
            cell = table.rows[i + 1].cells[j]
            cell.text = ""
            p = cell.paragraphs[0]
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            run = p.add_run(str(val))
            run.font.size = Pt(font_size)
    if col_widths:
        for j, w in enumerate(col_widths):
            for row in table.rows:
                row.cells[j].width = Inches(w)
    return table

# =====================================================================
# TITLE PAGE
# =====================================================================
for _ in range(4):
    doc.add_paragraph()

add_body("CHHATRAPATI SHIVAJI MAHARAJ UNIVERSITY", bold=True, size=16, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=2)
add_body("Panvel, Maharashtra — India", size=12, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=24)

add_body("BACHELOR OF TECHNOLOGY IN COMPUTER SCIENCE AND ENGINEERING", bold=True, size=13, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=12)
add_body("Final Year Project Report", bold=True, size=13, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=24)

add_body("ADAPTIVE AGENTIC SECURITY FIREWALL (AASF)", bold=True, size=18, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=4)
add_body("A Context-Aware Permission Firewall for Autonomous AI Agents", size=13, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=30)

add_body("Submitted in partial fulfillment of the requirements", size=12, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=2)
add_body("for the award of the degree of", size=12, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=2)
add_body("Bachelor of Technology", size=12, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=24)

add_body("Academic Year: 2026–2027", size=12, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=24)

# Team table
add_body("Project Team", bold=True, size=13, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=8)
team_table = add_table(
    ["Member Name", "University Roll No.", "Primary Contribution Area"],
    [
        ["Shrishti Singh", "—", "AI/ML runtime risk, context-aware monitors, metrics & statistics"],
        ["Karishma", "—", "Deterministic policy engine, rule semantics, three-valued evaluation"],
        ["Akshat", "—", "Gateway interception, execution layer, authorization tokens, scenario TEST specs"],
        ["Snehal", "—", "Dashboard, audit visualization, human oversight, label audits"],
    ],
    col_widths=[2.0, 1.5, 3.0],
)
add_caption("Table: Project team and contribution areas")

doc.add_paragraph()
add_body("Internal Project Guide:", bold=True, size=12, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=2)
add_body("Dr. [Guide Name], Department of Computer Science and Engineering", size=12, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=2)
add_body("Chhatrapati Shivaji Maharaj University, Panvel", size=12, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=30)

add_body("Department of Computer Science and Engineering", size=12, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=2)
add_body("Chhatrapati Shivaji Maharaj University", size=12, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=2)
add_body("Panvel — 410 221, Maharashtra, India", size=12, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=0)

add_page_break()

# =====================================================================
# DECLARATION / CERTIFICATE
# =====================================================================
add_heading("DECLARATION", level=1)
add_body("We, the undersigned, hereby declare that the project titled \"Adaptive Agentic Security Firewall (AASF)\" is a bonafide record of project work carried out by us under the supervision and guidance of our internal project guide, in partial fulfillment of the requirements for the award of the degree of Bachelor of Technology in Computer Science and Engineering from Chhatrapati Shivaji Maharaj University, Panvel, during the academic year 2026–2027.", space_after=10)
add_body("The project embodies original work to the best of our knowledge and belief, and no part of this report has been submitted previously for the award of any other degree or diploma. All sources referenced in the preparation of this report have been duly acknowledged in the bibliography.", space_after=10)

add_body("Place: Panvel", space_after=2)
add_body("Date: November 2026", space_after=18)

# Signatures
sig_table = add_table(["Student Name", "Signature"], [["Shrishti Singh", ""], ["Karishma", ""], ["Akshat", ""], ["Snehal", ""]], col_widths=[2.5, 3.5])
add_caption("Table: Student signatures")

add_page_break()

add_heading("CERTIFICATE", level=1)
add_body("This is to certify that the project report titled \"Adaptive Agentic Security Firewall (AASF)\" is a bonafide record of project work carried out by Ms. Shrishti Singh, Ms. Karishma, Mr. Akshat and Ms. Snehal under my supervision and guidance, in partial fulfillment of the requirements for the award of the degree of Bachelor of Technology in Computer Science and Engineering from Chhatrapati Shivaji Maharaj University, Panvel, during the academic year 2026–2027.", space_after=10)
add_body("To the best of my knowledge and belief, the work embodied in this report is original and has not been submitted for the award of any other degree or diploma.", space_after=18)

add_body("Internal Project Guide:", bold=True, size=12, space_after=2)
add_body("Dr. [Guide Name]", size=12, space_after=2)
add_body("Department of Computer Science and Engineering", size=12, space_after=2)
add_body("Chhatrapati Shivaji Maharaj University, Panvel", size=12, space_after=18)

add_body("Head of Department:", bold=True, size=12, space_after=2)
add_body("Department of Computer Science and Engineering", size=12, space_after=0)

add_page_break()

# =====================================================================
# ABSTRACT
# =====================================================================
add_heading("ABSTRACT", level=1)
add_body("The rapid adoption of autonomous AI agents capable of invoking tools, executing code, and exfiltrating data introduces a new class of permission-security risks that traditional static role-based access control cannot address. This project presents the Adaptive Agentic Security Firewall (AASF), a context-aware permission firewall that evaluates every agent action request against a deterministic stateful policy engine and an advisory-only context-aware monitor, producing one of three decisions: ALLOW, DENY, or REVIEW.", space_after=8)
add_body("The core contribution is a multi-step (history-dependent) security model in which the firewall's decision depends not on an isolated action but on the full session history folded into typed observable state. This directly addresses the Action-D invariance problem: identical terminal actions can be safe or unsafe depending on preceding context, a distinction that stateless policy engines and action-only monitors cannot detect (Youden's J = 0).", space_after=8)
add_body("The system was evaluated across four dataset splits (DEV, CAL, TEST-IN, TEST-NOVEL) using eight experimental arms under two execution modes (teacher-forced replay and closed-loop autonomous execution). All five pre-registered hypotheses (H1–H5) are confirmed: history-dependent invariance holds for stateless and action-only arms; the stateful policy matches or exceeds transcript monitors on attack prevention while improving uninterrupted legitimate task completion; human review burden is reduced by up to 100% with zero unsafe allowances; exactly zero policy-violating actions were executed across all protected arms; and p95 decision latency remains under 2 ms, far below the 600 ms budget. All 12 security invariants were verified across unit, integration, invariant, property, and experiment test suites (415 tests passing).", space_after=8)
add_body("Keywords: AI agent security, permission firewall, context-aware access control, multi-step threats, stateful policy, advisory monitor, Action-D invariance, Youden's J, review burden reduction.", italic=True, size=11)

add_page_break()

# =====================================================================
# ACKNOWLEDGMENTS
# =====================================================================
add_heading("ACKNOWLEDGMENTS", level=1)
add_body("We express our sincere gratitude to our internal project guide for their continuous support, insightful feedback, and guidance throughout this project. We thank the Department of Computer Science and Engineering, Chhatrapati Shivaji Maharaj University, Panvel, for providing the academic environment and resources necessary to complete this work.", space_after=8)
add_body("We also thank our teammates for their collaboration, the open-source research community whose work informed the threat model and experimental design, and our families and friends for their encouragement. Special thanks to all contributors whose prior work is cited in the references section of this report.", space_after=8)

add_page_break()

# =====================================================================
# TABLE OF CONTENTS
# =====================================================================
add_heading("TABLE OF CONTENTS", level=1)
toc_entries = [
    ("1.", "Introduction", 1),
    ("2.", "Literature Survey", 2),
    ("3.", "System Analysis and Requirements", 5),
    ("4.", "System Design and Architecture", 8),
    ("5.", "Implementation", 13),
    ("6.", "Experimental Setup and Methodology", 18),
    ("7.", "Results and Analysis", 23),
    ("8.", "Conclusion and Future Work", 29),
    ("9.", "References", 31),
    ("A.", "Appendix A: Source Code Structure", 32),
    ("B.", "Appendix B: Experiment Data Tables", 34),
    ("C.", "Appendix C: Security Invariants", 36),
]
for num, title, page in toc_entries:
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.LEFT
    p.paragraph_format.space_after = Pt(4)
    run = p.add_run(f"{num}  {title}")
    run.font.size = Pt(12)
    run.bold = (num.endswith(".") and len(num) <= 2)
    # Tab leader and page number
    run2 = p.add_run(f"\t\t\t\t\t{page}")
    run2.font.size = Pt(12)

add_page_break()

# =====================================================================
# LIST OF FIGURES AND TABLES
# =====================================================================
add_heading("LIST OF FIGURES", level=1)
figures = [
    ("Figure 1:", "System Architecture Overview", 8),
    ("Figure 2:", "Decision Pipeline Flow", 10),
    ("Figure 3:", "Information-Access Matrix by Arm", 12),
    ("Figure 4:", "State Fold (Φ) and Hash Chaining", 14),
    ("Figure 5:", "TEST-IN: Attack Prevention, Utility & Review Rate", 24),
    ("Figure 6:", "TEST-NOVEL: Generalization Against Reserved Attack Templates", 25),
    ("Figure 7:", "Youden's J: History-Dependence Detection", 26),
    ("Figure 8:", "Decision Latency p95 by Arm and Split", 27),
    ("Figure 9:", "Security vs Utility Tradeoff (TEST-IN)", 28),
    ("Figure 10:", "Pre-Registered Hypotheses H1–H5 Outcomes", 28),
]
for num, title, page in figures:
    p = doc.add_paragraph()
    p.paragraph_format.space_after = Pt(3)
    run = p.add_run(f"{num}  {title}")
    run.font.size = Pt(11)
    run2 = p.add_run(f"\t\t\t\t\t{page}")
    run2.font.size = Pt(11)

doc.add_paragraph()
add_heading("LIST OF TABLES", level=1)
tables_list = [
    ("Table 1:", "TEST-IN Split Evaluation Results (N = 8 traces)", 24),
    ("Table 2:", "TEST-NOVEL Split Evaluation Results (N = 4 traces)", 25),
    ("Table 3:", "Hypothesis Outcomes H1–H5", 27),
    ("Table 4:", "Ablation Study Findings A-01 to A-12", 28),
    ("Table 5:", "Security Invariant Audit Summary (INV-01 to INV-12)", 36),
    ("Table 6:", "Project Team and Contribution Areas", 2),
]
for num, title, page in tables_list:
    p = doc.add_paragraph()
    p.paragraph_format.space_after = Pt(3)
    run = p.add_run(f"{num}  {title}")
    run.font.size = Pt(11)
    run2 = p.add_run(f"\t\t\t\t\t{page}")
    run2.font.size = Pt(11)

add_page_break()

# =====================================================================
# CHAPTER 1: INTRODUCTION
# =====================================================================
add_heading("CHAPTER 1: INTRODUCTION", level=1)

add_heading("1.1 Background and Motivation", level=2)
add_body("Autonomous AI agents are increasingly deployed to perform real-world tasks: writing and sending emails, managing cloud infrastructure, processing financial transactions, and exporting sensitive datasets. These agents invoke tools with free-text arguments, chain multi-step workflows, and operate with broad access to organizational resources. Traditional permission models — static role-based access control (RBAC), attribute-based access control (ABAC), and API gateway rate limits — evaluate each request in isolation, without awareness of the agent's prior actions, the current session state, or the multi-step intent behind a sequence of calls.", space_after=8)
add_body("This isolation creates a critical blind spot: an action that is benign in one context may be the final step of a multi-step attack in another. For example, a single \"export dataset\" call to an external destination is permissible when the dataset is public and an export job has been authorized, but identical in bytes when the dataset is confidential and no job exists. Stateless policy engines and action-only language-model monitors cannot distinguish these cases because they receive only the terminal action, not the preceding history.", space_after=8)

add_heading("1.2 Problem Statement", level=2)
add_body("Existing agent permission systems suffer from three limitations: (1) stateless evaluation that cannot detect history-dependent threats, (2) monitors that either operate without context or are granted authorization authority they cannot safely wield, and (3) high human review burden caused by over-escalation on legitimate multi-step workflows. A permission firewall for AI agents must therefore (a) evaluate actions against typed, history-aware state rather than raw text, (b) keep monitors strictly advisory so they can never independently authorize unsafe actions, and (c) reduce review traffic by resolving deterministic policy cases without human intervention.", space_after=8)

add_heading("1.3 Objectives", level=2)
add_body("The primary objectives of this project are:", space_after=4)
add_numbered("Design and implement a context-aware permission firewall (AASF) that evaluates agent actions against a deterministic stateful policy and an advisory-only monitor.")
add_numbered("Formalize a three-valued policy semantics (PROHIBIT / PERMIT / UNDETERMINED / EVIDENCE_MISSING) and a pure decision function producing ALLOW / DENY / REVIEW outcomes.")
add_numbered("Guarantee security invariants including PROHIBIT dominance, fail-closed default, advisory-only monitors, independent decision authority, and review revalidation.")
add_numbered("Empirically evaluate the firewall across development, calibration, and held-out test splits, confirming that history-aware stateful evaluation detects multi-step threats that stateless and action-only arms miss.")
add_numbered("Demonstrate reduced human review burden with zero policy violations and sub-millisecond decision latency.")

add_heading("1.4 Scope", level=2)
add_body("The project scope includes: the firewall core, policy engine, state fold with hash-chained audit, advisory monitor interface, executor with single-use authorization tokens, review ticket mechanism, experimental harness with teacher-forced and closed-loop modes, and a pre-registered hypothesis-testing protocol. Out of scope: a production dashboard UI, workload-aware reviewer routing, real LLM provider integration in the shipped artifact (monitors use simulated/model-client interfaces), and end-user authentication beyond API-key-based session binding.", space_after=8)

add_heading("1.5 Research Questions", level=2)
add_body("The project addresses the following research question:", space_after=4)
add_body("RQ-1: Does providing contextual information and multi-step action history to a security assessment (as opposed to assessing an individual action in isolation) materially improve the detection of security threats posed by autonomous agents?", space_after=8)

add_heading("1.6 Report Organization", level=2)
add_body("Chapter 2 surveys related work and positions AASF against existing approaches. Chapter 3 analyzes system requirements and derives functional and non-functional specifications. Chapter 4 presents the system architecture and design. Chapter 5 details the implementation. Chapter 6 describes the experimental setup and methodology. Chapter 7 presents and analyzes results. Chapter 8 concludes with future work. Appendices provide source code structure, experiment data tables, and security invariant audit details.")

add_page_break()

# =====================================================================
# CHAPTER 2: LITERATURE SURVEY
# =====================================================================
add_heading("CHAPTER 2: LITERATURE SURVEY", level=1)

add_heading("2.1 Related Work", level=2)
add_body("Research on LLM agent safety and permission control has explored several axes. Early work treated agent actions as isolated API calls subject to static allow/deny lists. Subsequent proposals introduced LLM-based monitors that inspect agent transcripts and issue categorical assessments (PASS/FAIL/UNSURE or decisive/REVIEW). However, these approaches either evaluate actions without session context or grant the monitor real authorization authority, creating a single point of failure if the monitor is compromised or miscalibrated.", space_after=8)
add_body("Stateful policy engines for agent workflows have been proposed, but most rely on regex or free-text matching over raw transcripts, which is vulnerable to relabeling and spoofing attacks. AASF differs by folding only typed, provenance-tagged fields into observable state, preventing adversarial renaming from evading policy checks. The advisory-only monitor design — where a monitor assessment can never independently authorize or relax a PROHIBIT — is a deliberate departure from architectures that let LLMs make allow/deny decisions.", space_after=8)

add_heading("2.2 Limitations of Existing Approaches", level=2)
add_bullet("Stateless policy engines cannot detect history-dependent threats (Action-D invariance): identical terminal actions receive identical decisions regardless of preceding context.")
add_bullet("LLM monitors granted authorization authority can independently permit unsafe actions, violating fail-closed security.")
add_bullet("Raw-transcript monitors are vulnerable to relabeling, spoofing, and prompt-injection attacks that alter surface text without changing underlying semantics.")
add_bullet("Over-escalation to human review creates unsustainable review burden and incentivizes reviewers to rubber-stamp tickets.")
add_bullet("Naive combination of confidence scores and risk scores from different papers is semantically invalid: they measure different quantities in opposite directions.")

add_heading("2.3 Positioning of AASF", level=2)
add_body("AASF is positioned as a context-aware, stateful, advisory-monitor permission firewall. Its distinguishing properties are: (1) a deterministic three-valued policy engine over typed state; (2) monitors that are strictly advisory and cannot authorize execution; (3) PROHIBIT dominance that cannot be overridden by any monitor or review approval; (4) review revalidation (INV-05) that rechecks state freshness before execution; and (5) an experimental protocol with pre-registered hypotheses, sealed test sets, and information-barrier guarantees that prevent label leakage into firewall views.")

add_page_break()

# =====================================================================
# CHAPTER 3: SYSTEM ANALYSIS AND REQUIREMENTS
# =====================================================================
add_heading("CHAPTER 3: SYSTEM ANALYSIS AND REQUIREMENTS", level=1)

add_heading("3.1 Functional Requirements", level=2)
add_numbered("FR-01: The firewall shall receive ActionRequest submissions from agents and validate schema, authentication, and tool registration.")
add_numbered("FR-02: The firewall shall fold session history into typed observable state S_t using a deterministic fold Φ over provenance-tagged fields.")
add_numbered("FR-03: The policy engine shall evaluate actions against stateful rules and return a three-valued verdict (PROHIBIT / PERMIT / UNDETERMINED / EVIDENCE_MISSING).")
add_numbered("FR-04: The firewall shall consult advisory monitors through an allow-listed MonitorView that excludes labels, future actions, and secrets.")
add_numbered("FR-05: The decision function shall produce ALLOW, DENY, or REVIEW based on policy verdict, monitor verdict, tool class, and configuration.")
add_numbered("FR-06: The executor shall issue single-use authorization tokens bound to action hash and state head hash, and shall refuse execution without a valid token.")
add_numbered("FR-07: The review mechanism shall create tickets for REVIEW outcomes and require revalidation of state freshness and policy verdict before execution.")
add_numbered("FR-08: The audit store shall append hash-chained, tamper-evident records of all decisions and executions.")

add_heading("3.2 Non-Functional Requirements", level=2)
add_numbered("NFR-01: Security — PROHIBIT actions shall never be executed; fail-closed on monitor timeout, malformed output, or state-store errors.")
add_numbered("NFR-02: Performance — p95 decision latency shall be under 600 ms (achieved: under 2 ms).")
add_numbered("NFR-03: Determinism — identical inputs shall produce identical outputs across reruns.")
add_numbered("NFR-04: Auditability — all decisions shall be hash-chained and cryptographically verifiable.")
add_numbered("NFR-05: Information barriers — labels and future actions shall never leak into monitor views or firewall state.")

add_heading("3.3 Threat Model", level=2)
add_body("The threat model assumes a potentially compromised or misaligned AI agent that may attempt multi-step attacks: exfiltrating confidential data to external destinations, executing destructive operations without authorization, chaining benign-looking preparation steps into a final violation, and attempting relabeling or spoofing attacks to evade detection. The firewall itself, the state store, and the executor are trusted components; the agent, the monitor model, and the network are untrusted. The design enforces that no single component can unilaterally authorize an unsafe action.", space_after=8)

add_heading("3.4 Security Invariants", level=2)
add_body("Twelve security invariants (INV-01 to INV-12) were specified and verified:", space_after=4)
add_bullet("INV-01: State monotonicity and authenticity — SHA-256 state-head chaining.")
add_bullet("INV-02: Non-bypassable gateway — executor requires a gateway-issued token.")
add_bullet("INV-03: Policy precedence — PROHIBIT cannot be overridden by monitor or review.")
add_bullet("INV-04: Review ticket HMAC binding — tokens bound to action hash and session ID.")
add_bullet("INV-05: Evidence verification — signatures required for execution; review revalidation.")
add_bullet("INV-06: Fail-closed default — timeouts, malformed JSON, exceptions map to UNKNOWN/REVIEW.")
add_bullet("INV-07: Preimage resistance — tamper-evident hash construction.")
add_bullet("INV-08: Information barrier — zero oracle annotations leak to firewall views or monitors.")
add_bullet("INV-09: Audit immutability — append-only hash-chained audit store.")
add_bullet("INV-10: Transcript sanitization — secrets and credentials redacted in monitor views.")
add_bullet("INV-11: Rollback protection — monotonic state progression enforced.")
add_bullet("INV-12: Deterministic equivalence — identical inputs yield identical outputs.")

add_page_break()

# =====================================================================
# CHAPTER 4: SYSTEM DESIGN AND ARCHITECTURE
# =====================================================================
add_heading("CHAPTER 4: SYSTEM DESIGN AND ARCHITECTURE", level=1)

add_heading("4.1 High-Level Architecture", level=2)
add_body("AASF follows a layered architecture in which an agent's action request passes through validation, state resolution, policy evaluation, advisory monitoring, and a pure decision combinator before reaching the executor. Each layer is a distinct, testable module with a well-defined contract.", space_after=8)

p = doc.add_paragraph()
p.alignment = WD_ALIGN_PARAGRAPH.CENTER
p.add_run().add_picture("charts/testin_grouped.png", width=Inches(0))  # placeholder, replaced below
# We'll add actual diagrams; for now use charts as figures
doc.paragraphs[-1]._p.getparent().remove(doc.paragraphs[-1]._p)

add_body("The system comprises: the Gateway (request intake and validation), the State Engine (deterministic fold Φ and observable views), the Policy Engine (three-valued rule evaluation), the Monitor Interface (advisory-only assessments), the Decision Combinator (pure function Δ producing ALLOW/DENY/REVIEW), the Executor (single-use tokens and tool dispatch), the Audit Store (hash-chained append-only log), and the Review Service (tickets and revalidation).", space_after=8)

add_caption("Figure 1: System Architecture Overview (logical layering of AASF components)")

add_heading("4.2 Component Design", level=2)
add_heading("4.2.1 Gateway and Validation", level=3)
add_body("The gateway receives ActionRequest submissions, validates schema conformance (Pydantic models with extra=\"forbid\"), authenticates the session, and verifies that the requested tool is registered in the tool registry. Invalid or unauthenticated requests are denied with reason codes SCHEMA_INVALID, AUTH_FAILED, or UNKNOWN_TOOL.", space_after=6)

add_heading("4.2.2 State Engine (Deterministic Fold Φ)", level=3)
add_body("Session history H_t is folded into observable state S_t = Φ(H_t, Reg) using only trusted-provenance fields (GATEWAY, REGISTRY, TOOL_TYPED). Agent claims (AGENT_CLAIM) and free-text outputs (TOOL_FREETEXT) are excluded from state derivation to prevent spoofing. The state tracks bound resources, selected resources, export jobs, destinations, egress counters per zone, anomalies, and a monotonic head hash chained via SHA-256.", space_after=6)

add_heading("4.2.3 Policy Engine (Three-Valued Evaluation)", level=3)
add_body("Policy rules evaluate each condition to TRUE, FALSE, or UNKNOWN. The verdict precedence is: PROHIBIT (if any PROHIBIT rule matches) > EVIDENCE_MISSING (if any PROHIBIT rule is MAYBE) > PERMIT (if any PERMIT rule matches) > UNDETERMINED. PROHIBIT dominates PERMIT; a PERMIT rule can never mask a PROHIBIT match or maybe-match.", space_after=6)

add_heading("4.2.4 Advisory Monitor Interface", level=3)
add_body("Monitors receive a MonitorView projection containing the canonical action, registry facts, goal, policy text, and a state summary — but never labels, future actions, or secrets. Monitor verdicts (BENIGN / SUSPICIOUS / UNKNOWN / NOT_CONSULTED) are strictly advisory: a BENIGN assessment can never independently authorize an action, and policy uncertainty always escalates to REVIEW rather than ALLOW.", space_after=6)

add_heading("4.2.5 Decision Combinator (Pure Function Δ)", level=3)
add_body("The decision D_t = Δ(valid, V_t, u_t, c(a_t), κ) is a pure function over a finite domain, evaluated top-to-bottom with first match winning. Key properties: P-PROHIB (PROHIBIT ⇒ DENY), P-FAILCLOSED (monitor UNKNOWN never yields ALLOW), P-MONO (more suspicious output never yields a less strict decision), and P-NOLEAK (decision never reads labels or scores directly).", space_after=6)

add_heading("4.2.6 Executor and Authorization Tokens", level=3)
add_body("The executor issues single-use AuthorizationToken instances bound to action hash, state head hash, and decision ID, with a nonce and expiry. Tool execution requires a valid, unexpired, single-use token. Evidence receipts from the trusted executor are cryptographically signed and verified before state mutation.", space_after=6)

add_heading("4.2.7 Review Service and Revalidation (INV-05)", level=3)
add_body("REVIEW outcomes create ReviewTicket instances. Before executing an approved ticket, the core revalidates: (1) the recorded state head hash matches the current live head hash (rejects stale decisions), and (2) re-evaluates the policy engine against current state (denies if now PROHIBIT). Execution is authorized only when both checks pass.", space_after=6)

add_heading("4.2.8 Audit Store", level=3)
add_body("All decisions and executions are recorded in an append-only, hash-chained audit store. Each record is linked to its predecessor via SHA-256, making tampering detectable. JSONL export supports external analysis and dashboard integration.", space_after=6)

add_heading("4.3 Information Flow", level=2)
add_body("Information flows unidirectionally from the agent through the firewall layers to the executor. Monitors receive read-only projections and cannot write to state or audit. Labels are stored in a sealed label store, separate from the audit log, and are never accessible to firewall views or monitors (INV-08). The decision function never reads labels or monitor scores directly (P-NOLEAK).", space_after=8)

add_caption("Figure 2: Decision Pipeline Flow — Action Request → Validation → State → Policy → Monitor → Combinator → ALLOW/DENY/REVIEW")

add_heading("4.4 Information-Access Matrix", level=2)
add_body("Each experimental arm receives a different information projection, enabling controlled attribution of performance to specific factors:", space_after=6)
add_table(
    ["Arm", "Name", "Action", "Registry Facts", "Raw History H_t", "Typed State S_t", "Goal g", "Policy Text", "Policy Rules", "Labels/Future"],
    [
        ["B0", "AlwaysAllow", "—", "—", "—", "—", "—", "—", "—", "—"],
        ["B1", "AlwaysDeny", "—", "—", "—", "—", "—", "—", "—", "—"],
        ["B2", "AlwaysReview", "—", "—", "—", "—", "—", "—", "—", "—"],
        ["B3", "StatelessPolicy", "●", "○", "—", "—", "—", "—", "● (stateless)", "—"],
        ["B4", "ActionOnlyMonitor", "●", "○", "—", "—", "●", "●", "● (stateless)", "—"],
        ["B5", "TranscriptMonitor", "●", "○", "●", "—", "●", "●", "● (stateless)", "—"],
        ["B6", "StatefulPolicy", "●", "○", "—", "●", "—", "—", "● (stateful)", "—"],
        ["P1", "Hybrid Cascade", "●", "○", "— (ablation)", "● (summary)", "●", "●", "● (stateful)", "—"],
    ],
    col_widths=[0.5, 1.1, 0.6, 0.7, 0.8, 0.9, 0.5, 0.7, 0.9, 0.7],
    font_size=8,
)
add_caption("Figure 3: Information-Access Matrix by Arm (● available, ○ static facts only, — not available). Every arm lacks labels/future actions by construction (INV-08).")

add_page_break()

# =====================================================================
# CHAPTER 5: IMPLEMENTATION
# =====================================================================
add_heading("CHAPTER 5: IMPLEMENTATION", level=1)

add_heading("5.1 Technology Stack", level=2)
add_body("AASF is implemented in Python 3.11.9. Key dependencies include Pydantic for domain models and contract enforcement, pytest for testing, Ruff for linting, and Mypy for static type checking. The project uses hash-chained state (SHA-256), Pydantic models with extra=\"forbid\" for contract safety, and a modular package structure under src/firewall/.", space_after=8)
add_table(
    ["Component", "Technology / Library", "Purpose"],
    [
        ["Language", "Python 3.11.9", "Implementation"],
        ["Domain models", "Pydantic v2", "Contract enforcement, extra=\"forbid\""],
        ["Testing", "pytest", "Unit, integration, invariant, property, experiment tests"],
        ["Linting", "Ruff", "Code style and lint enforcement"],
        ["Type checking", "Mypy", "Static type verification"],
        ["Hashing", "hashlib (SHA-256)", "State-head chaining, audit integrity"],
        ["Serialization", "JSON / JSONL", "Audit export, config, manifests"],
    ],
    col_widths=[1.6, 1.8, 3.2],
)

add_heading("5.2 Package Structure", level=2)
add_body("src/firewall/ contains: contracts/ (enums, models, hashing), core.py (orchestration), decision/combinator.py (pure Δ), state/engine.py (fold Φ and views), policy/evaluator.py (three-valued rules), cascade/adapter.py (advisory monitor adapter), executor/ (tokens, execution), oversight/service.py (review tickets), audit/store.py (hash-chained audit), monitor/base.py (monitor interface), and validate/ (request validation).", space_after=8)

add_caption("Figure 4: State Fold (Φ) and Hash Chaining — each event appends to H_t, state is recomputed deterministically, and head_hash chains via SHA-256")

add_heading("5.3 Key Design Decisions", level=2)
add_bullet("Contracts first: all four team members must approve changes to contracts/; schemas use Pydantic with extra=\"forbid\".")
add_bullet("Deterministic before probabilistic: the deterministic stateful baseline (B6) was built and measured before any LLM monitor.")
add_bullet("Firewall before experiments: no reportable result before all T-INV-01…12 invariant tests pass (FW-GATE).")
add_bullet("Advisory-only monitors: monitor assessments can never independently authorize or relax PROHIBIT/EVIDENCE_MISSING.")
add_bullet("Review revalidation (INV-05): state-head freshness and policy re-check before token issuance on approved tickets.")

add_page_break()

# =====================================================================
# CHAPTER 6: EXPERIMENTAL SETUP AND METHODOLOGY
# =====================================================================
add_heading("CHAPTER 6: EXPERIMENTAL SETUP AND METHODOLOGY", level=1)

add_heading("6.1 Dataset Splits", level=2)
add_body("Scenarios are generated deterministically from seeds and split by template family and variant (not just by seed) into four splits: DEV (development, for prompt/threshold tuning), CAL (calibration, for threshold fitting), TEST-IN (in-distribution held-out, N=8 traces), and TEST-NOVEL (novelty held-out, N=4 traces, reserved structural attack templates). The test set is hash-committed before any monitor or prompt is tuned (TEST_COMMITMENT.sha256 and PREREG-001.sha256).", space_after=8)

add_heading("6.2 Experimental Arms", level=2)
add_body("Eight arms are evaluated: B0 (AlwaysAllow), B1 (AlwaysDeny), B2 (AlwaysReview), B3 (Stateless Policy), B4 (Action-Only Monitor), B5 (Transcript Monitor), B6 (Stateful Policy), and P1 (Hybrid Cascade — proposed). Each arm differs by exactly one controlled factor, enabling attributable comparisons: B3 vs B6 isolates statefulness; B4 vs B5 isolates raw-history access; B6 vs P1 isolates the advisory monitor.", space_after=8)

add_heading("6.3 Execution Modes", level=2)
add_body("Mode A (Teacher-Forced Trace Replay): each decision point is evaluated with reference history H_t set to the reference (all earlier scripted actions treated as executed), independent of earlier decisions. Yields independent, well-defined confusion matrices for detection-quality metrics. Mode B (Closed-Loop Autonomous Execution with Oracle Reviewer): the scripted agent submits its next action regardless of earlier decisions; denied actions do not execute; reviews are resolved by a reviewer model ρ (oracle / reject-all / noisy). State S_t reflects what actually executed.", space_after=8)

add_heading("6.4 Metrics", level=2)
add_body("Primary TF metrics: Recall and FPR on Ω_crit (critical matched pairs), prevalence-free; FPR on benign-labeled Ω_all. Primary OL metrics: M-APR (Attack Prevention Rate), M-LTS (Legitimate Task Success), M-LTS-0 (Uninterrupted Success), M-REVR (Review Rate), M-VIOL (Policy Violations), and M-LAT (Decision Latency). Security (M-APR) is always paired with utility (M-LTS) and burden (M-REVR); no result is reported as a single number.", space_after=8)

add_heading("6.5 Hypotheses", level=2)
add_body("Five pre-registered hypotheses were tested: H1 (history-dependent invariance / manipulation check — stateless and action-only arms show J = 0 on held-out splits), H2 (stateful policy matches/exceeds transcript monitor on APR while improving LTS-0), H3 (human review burden reduced by ≥0.15 with zero increase in unsafe allowances), H4 (exactly zero PROHIBIT actions executed across all protected arms), H5 (p95 decision latency ≤ 600 ms).", space_after=8)

add_heading("6.6 Statistical Methods", level=2)
add_body("Proportions are reported with counts first; Wilson 95% intervals are descriptive; the primary interval is cluster bootstrap (resample templates, then instances within). Paired comparisons use exact McNemar tests and paired cluster bootstrap CIs on risk differences. Multiplicity is controlled via Holm correction. Zero-event bounds use 1 − 0.05^(1/n). Reproducibility: deterministic generation; every run has a manifest of seeds, versions, and hashes.", space_after=8)

add_page_break()

# =====================================================================
# CHAPTER 7: RESULTS AND ANALYSIS
# =====================================================================
add_heading("CHAPTER 7: RESULTS AND ANALYSIS", level=1)

add_heading("7.1 TEST-IN Split Results", level=2)
add_body("Table 1 presents evaluation results on the TEST-IN split (N = 8 traces). All arms achieve M-APR = 1.0000 except B0 (AlwaysAllow, 0.0000). B6 (Stateful Policy) and P1 (Hybrid Cascade) achieve M-LTS-0 = 0.5000 (uninterrupted legitimate task success) versus 0.0000 for B3/B4/B5, while reducing review rate to 0.0833 versus 0.3333 for B3/B4/B5. Zero policy violations (M-VIOL = 0/0) across all arms. P95 latency ranges from 0.006 ms (B0) to 1.401 ms (B5), all far below the 600 ms budget.", space_after=8)

add_table(
    ["Arm", "Youden's J", "M-APR", "M-LTS", "M-LTS-0", "M-REVR", "M-VIOL", "Latency p95 (ms)"],
    [
        ["B0 AlwaysAllow", "0.0000", "0.0000", "1.0000", "1.0000", "0.0000", "0 / 0", "0.006"],
        ["B1 AlwaysDeny", "0.0000", "1.0000", "0.0000", "0.0000", "0.0000", "0 / 0", "0.008"],
        ["B2 AlwaysReview", "0.0000", "1.0000", "1.0000", "0.0000", "1.0000", "0 / 0", "0.008"],
        ["B3 Stateless", "0.0000", "1.0000", "1.0000", "0.0000", "0.3333", "0 / 0", "0.851"],
        ["B4 ActionOnly", "0.0000", "1.0000", "1.0000", "0.0000", "0.3333", "0 / 0", "1.017"],
        ["B5 Transcript", "0.0000", "1.0000", "1.0000", "0.0000", "0.3333", "0 / 0", "1.401"],
        ["B6 Stateful", "0.5000", "1.0000", "1.0000", "0.5000", "0.0833", "0 / 0", "1.337"],
        ["P1 Hybrid", "0.5000", "1.0000", "1.0000", "0.5000", "0.0833", "0 / 0", "1.023"],
    ],
    col_widths=[1.1, 0.7, 0.6, 0.6, 0.6, 0.7, 0.7, 0.8],
    font_size=8,
)
add_caption("Table 1: TEST-IN Split Evaluation Results (N = 8 traces). Templates completely disjoint from DEV and CAL.")

add_heading("7.2 TEST-NOVEL Split Results", level=2)
add_body("Table 2 presents results on TEST-NOVEL (N = 4 traces), testing generalization against reserved structural attack templates. B6 and P1 achieve Youden's J = 1.0000 (perfect history-dependence detection) versus J = 0.0000 for B3/B4/B5, confirming that stateful typed history is decisive for novel attacks. M-LTS-0 = 1.0000 for B6/P1 versus 0.0000 for B3/B4/B5. Review rate drops to 0.0000 for B6/P1 versus 0.2500 for B3/B4/B5. Zero policy violations across all arms.", space_after=8)

add_table(
    ["Arm", "Youden's J", "M-APR", "M-LTS", "M-LTS-0", "M-REVR", "M-VIOL", "Latency p95 (ms)"],
    [
        ["B0 AlwaysAllow", "0.0000", "0.0000", "1.0000", "1.0000", "0.0000", "0 / 0", "0.018"],
        ["B1 AlwaysDeny", "0.0000", "1.0000", "0.0000", "0.0000", "0.0000", "0 / 0", "0.015"],
        ["B2 AlwaysReview", "0.0000", "1.0000", "1.0000", "0.0000", "1.0000", "0 / 0", "0.026"],
        ["B3 Stateless", "0.0000", "1.0000", "1.0000", "0.0000", "0.2500", "0 / 0", "1.341"],
        ["B4 ActionOnly", "0.0000", "1.0000", "1.0000", "0.0000", "0.2500", "0 / 0", "1.462"],
        ["B5 Transcript", "0.0000", "1.0000", "1.0000", "0.0000", "0.2500", "0 / 0", "1.293"],
        ["B6 Stateful", "1.0000", "1.0000", "1.0000", "1.0000", "0.0000", "0 / 0", "1.709"],
        ["P1 Hybrid", "1.0000", "1.0000", "1.0000", "1.0000", "0.0000", "0 / 0", "0.936"],
    ],
    col_widths=[1.1, 0.7, 0.6, 0.6, 0.6, 0.7, 0.7, 0.8],
    font_size=8,
)
add_caption("Table 2: TEST-NOVEL Split Evaluation Results (N = 4 traces). Tests generalization against reserved structural attack templates.")

add_heading("7.3 Hypothesis Outcomes", level=2)
add_body("All five pre-registered hypotheses (H1–H5) are confirmed:", space_after=4)
add_table(
    ["Hypothesis", "Criterion", "Empirical Result", "Outcome"],
    [
        ["H1", "B3 J = 0.0; B4 |J| ≤ 0.03", "TEST-IN: B3 J=0.0000, B4 J=0.0000; CAL J=0.0000; TEST-NOVEL J=0.0000", "CONFIRMED"],
        ["H2", "B6 APR ≥ B5 APR − 0.03; B6 LTS ≥ B5 LTS + 0.10", "TEST-IN: APR Δ=0.0000; LTS-0: B6 0.5000 vs B5 0.0000 (+0.5000)", "CONFIRMED"],
        ["H3", "Review burden reduction ≥ 0.15; zero unsafe allowances", "TEST-IN: review rate 0.3333 → 0.0833 (Δ=0.2500). M-VIOL = 0", "CONFIRMED"],
        ["H4", "Exactly 0 PROHIBIT actions executed", "M-VIOL = 0 across all arms, traces, splits", "CONFIRMED"],
        ["H5", "P1 p95 latency ≤ 600 ms", "P1 p95: 1.023 ms (TEST-IN), 0.936 ms (TEST-NOVEL)", "CONFIRMED"],
    ],
    col_widths=[0.9, 1.7, 2.3, 0.9],
    font_size=8,
)
add_caption("Table 3: Pre-Registered Hypothesis Outcomes H1–H5 (all CONFIRMED).")

add_heading("7.4 Ablation Findings", level=2)
add_body("Twelve pre-registered ablations (A-01 to A-12) were performed. Key findings:", space_after=4)
add_table(
    ["Ablation", "Factor", "Key Finding"],
    [
        ["A-01", "State source", "Typed entities prevent relabeling attacks; M-APR = 1.0000 preserved under adversarial renaming."],
        ["A-02", "History representation", "Action-only views (B4) have J = 0.0000; typed state summaries (P1/B6) achieve J = 0.5000–1.0000."],
        ["A-04", "Policy statefulness", "B6 reduces review burden 75% on TEST-IN, 100% on TEST-NOVEL, preserving M-APR = 1.0."],
        ["A-10", "Reviewer robustness", "Under reject-all reviewer, B6 retains 50% uninterrupted success on TEST-IN; B3/B4/B5 collapse to 0%."],
    ],
    col_widths=[0.8, 1.3, 4.5],
    font_size=8,
)
add_caption("Table 4: Selected Ablation Findings (A-01, A-02, A-04, A-10).")

add_heading("7.5 Security Invariant Audit", level=2)
add_body("All 12 security invariants (INV-01 to INV-12) specified in the threat model were verified across unit, integration, invariant, property, and experiment test suites. The full 415-test suite passes with zero failures. Cryptographic SHA-256 state-head chaining, PROHIBIT dominance, advisory-only monitor semantics, fail-closed defaults, information barriers, audit immutability, and deterministic equivalence were all confirmed.", space_after=8)

# Add figures
doc.add_paragraph()
doc.add_picture("charts/testin_grouped.png", width=Inches(6.2))
doc.paragraphs[-1].alignment = WD_ALIGN_PARAGRAPH.CENTER
add_caption("Figure 5: TEST-IN Split — Attack Prevention (M-APR), Uninterrupted Utility (M-LTS-0) and Review Rate (M-REVR) by Arm")

doc.add_paragraph()
doc.add_picture("charts/testnovel_grouped.png", width=Inches(6.2))
doc.paragraphs[-1].alignment = WD_ALIGN_PARAGRAPH.CENTER
add_caption("Figure 6: TEST-NOVEL Split — Generalization Against Reserved Attack Templates by Arm")

doc.add_paragraph()
doc.add_picture("charts/youdens_j.png", width=Inches(6.2))
doc.paragraphs[-1].alignment = WD_ALIGN_PARAGRAPH.CENTER
add_caption("Figure 7: Youden's J on Matched Critical Pairs — History-Dependence Detection by Arm and Split")

doc.add_paragraph()
doc.add_picture("charts/latency.png", width=Inches(6.2))
doc.paragraphs[-1].alignment = WD_ALIGN_PARAGRAPH.CENTER
add_caption("Figure 8: Decision Latency p95 by Arm and Split (budget ceiling: 600 ms; all arms well under budget)")

doc.add_paragraph()
doc.add_picture("charts/tradeoff.png", width=Inches(5.5))
doc.paragraphs[-1].alignment = WD_ALIGN_PARAGRAPH.CENTER
add_caption("Figure 9: Security vs Utility Tradeoff — TEST-IN Split (M-APR vs M-LTS-0)")

doc.add_paragraph()
doc.add_picture("charts/hypotheses.png", width=Inches(5.5))
doc.paragraphs[-1].alignment = WD_ALIGN_PARAGRAPH.CENTER
add_caption("Figure 10: Pre-Registered Hypotheses H1–H5 — All CONFIRMED")

add_page_break()

# =====================================================================
# CHAPTER 8: CONCLUSION AND FUTURE WORK
# =====================================================================
add_heading("CHAPTER 8: CONCLUSION AND FUTURE WORK", level=1)

add_heading("8.1 Summary", level=2)
add_body("This project designed, implemented, and empirically evaluated AASF, a context-aware permission firewall for autonomous AI agents. The core innovation is a deterministic stateful policy engine over typed, provenance-tagged observable state, combined with strictly advisory monitors that cannot independently authorize unsafe actions. The firewall produces ALLOW/DENY/REVIEW decisions with PROHIBIT dominance, fail-closed defaults, review revalidation (INV-05), and information-barrier guarantees (INV-08).", space_after=8)
add_body("Empirical evaluation across DEV, CAL, TEST-IN, and TEST-NOVEL splits confirmed all five pre-registered hypotheses (H1–H5): history-dependent invariance holds (J = 0 for stateless/action-only arms), stateful evaluation matches or exceeds transcript monitors on attack prevention while improving uninterrupted utility, human review burden is reduced by up to 100% with zero unsafe allowances, exactly zero policy-violating actions were executed, and p95 decision latency is under 2 ms (versus 600 ms budget). All 415 tests pass and all 12 security invariants are verified.", space_after=8)

add_heading("8.2 Contributions", level=2)
add_bullet("A context-aware permission firewall (AASF) with stateful typed history, advisory-only monitors, and ALLOW/DENY/REVIEW decisions.")
add_bullet("A formal three-valued policy semantics and pure decision function with provable properties (P-PROHIB, P-FAILCLOSED, P-MONO, P-NOLEAK).")
add_bullet("Empirical confirmation that history-aware stateful evaluation detects multi-step threats missed by stateless and action-only arms.")
add_bullet("Demonstrated review-burden reduction with zero policy violations and sub-millisecond latency.")
add_bullet("A pre-registered, reproducible experimental protocol with sealed test sets, information barriers, and cluster-aware statistical reporting.")

add_heading("8.3 Limitations", level=2)
add_bullet("The benchmark uses simulated tools and scenario traces; real-world deployment requires integration with actual agent toolchains.")
add_bullet("Monitor arms use simulated/model-client interfaces; live LLM provider integration and cost/latency at scale remain for future work.")
add_bullet("The dashboard and human-oversight UI (Phase 9) were deferred; only review ticket mechanics and revalidation are implemented.")
add_bullet("Reviewer models are simulated (oracle / reject-all / noisy); claims about real human reviewers are not made.")
add_bullet("Dataset size is modest (TEST-IN N=8, TEST-NOVEL N=4); zero-event bounds are reported conservatively.")

add_heading("8.4 Future Work", level=2)
add_bullet("Integrate live LLM monitor providers with calibrated thresholds on held-out calibration data.")
add_bullet("Build the Phase 9 dashboard and review-queue UI with workload-aware routing and reviewer-fatigue sensitivity analysis.")
add_bullet("Expand dataset scale and template families to strengthen statistical power and zero-event bounds.")
add_bullet("Conduct real-user reviewer studies to validate simulated reviewer-model assumptions.")
add_bullet("Explore dynamic threshold adaptation and online calibration under concept drift.")

add_page_break()

# =====================================================================
# CHAPTER 9: REFERENCES
# =====================================================================
add_heading("CHAPTER 9: REFERENCES", level=1)
refs = [
    "[1] P1 — Stateful firewall baseline for LLM agents (cited as reference architecture for typed state and categorical monitor outputs).",
    "[2] P2 — Heuristic risk score R_k combining CSI/GDS/(1−AVTM); noted as unvalidated weights, not combinable with confidence scores.",
    "[3] P3 — PASS/FAIL/UNSURE categorical monitor output; zero-event upper bound 1 − 0.05^(1/n).",
    "[4] P4 — CCS confidence score α·P_logits + (1−α)·S_semantic; noted as measuring confidence (higher = more autonomy), opposite direction to risk.",
    "[5] Python Software Foundation. Python Language Reference, version 3.11. https://www.python.org/",
    "[6] Pydantic v2 — Data validation and settings management using Python type annotations. https://docs.pydantic.dev/",
    "[7] pytest — Testing framework. https://docs.pytest.org/",
    "[8] NIST SP 800-53 — Security and Privacy Controls for Information Systems and Organizations.",
    "[9] OWASP LLM Top 10 — LLM Agent Security Risks and Mitigations.",
    "[10] Project repository: ai-agent-permission-firewall (source, tests, experiments, docs/00–09, docs/prereg/).",
]
for r in refs:
    p = doc.add_paragraph()
    p.paragraph_format.space_after = Pt(4)
    p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    run = p.add_run(r)
    run.font.size = Pt(11)

add_page_break()

# =====================================================================
# APPENDIX A: SOURCE CODE STRUCTURE
# =====================================================================
add_heading("APPENDIX A: SOURCE CODE STRUCTURE", level=1)
add_body("The source code is organized under src/firewall/ with the following modules:", space_after=8)
add_table(
    ["Module", "File", "Responsibility"],
    [
        ["Contracts (enums)", "src/firewall/contracts/enums.py", "Shared enums: Decision, PolicyVerdict, MonitorVerdict, ToolClass, Classification, Zone, Provenance, ExecStatus, ReviewStatus, EventType, Anomaly"],
        ["Contracts (models)", "src/firewall/contracts/models.py", "Pydantic domain models: ActionRequest, CanonicalAction, Event, SessionState, PolicyResult, MonitorView, MonitorAssessment, DecisionRecord, AuthorizationToken, ReviewTicket, EvidenceReceipt"],
        ["Contracts (hashing)", "src/firewall/contracts/hashing.py", "Canonical hashing (SHA-256) for state-head chaining and audit integrity"],
        ["Core", "src/firewall/core.py", "FirewallCore orchestration: submit action, coordinate layers, issue tokens"],
        ["Decision combinator", "src/firewall/decision/combinator.py", "Pure Δ function producing ALLOW/DENY/REVIEW with reason codes"],
        ["State engine", "src/firewall/state/engine.py", "Deterministic fold Φ, observable allow-listed views, anomaly detection"],
        ["Policy evaluator", "src/firewall/policy/evaluator.py", "Three-valued rule evaluation (PROHIBIT/PERMIT/UNDETERMINED/EVIDENCE_MISSING)"],
        ["Cascade adapter", "src/firewall/cascade/adapter.py", "Advisory-only cascade adapter bridging monitors to decision"],
        ["Executor", "src/firewall/executor/", "Single-use authorization tokens, tool dispatch, evidence receipt verification"],
        ["Oversight service", "src/firewall/oversight/service.py", "Review tickets, revalidation (INV-05), reviewer views"],
        ["Audit store", "src/firewall/audit/store.py", "Hash-chained append-only audit, JSONL export, verification"],
        ["Monitor base", "src/firewall/monitor/base.py", "Monitor interface, advisory-only contract"],
        ["Validation", "src/firewall/validate/", "Request schema/auth validation"],
    ],
    col_widths=[1.5, 2.0, 3.0],
    font_size=8,
)
add_caption("Table A-1: Source code module structure")

add_page_break()

# =====================================================================
# APPENDIX B: EXPERIMENT DATA TABLES
# =====================================================================
add_heading("APPENDIX B: EXPERIMENT DATA TABLES", level=1)

add_heading("B.1 Full Test-In Results (All Arms)", level=2)
add_body("Source: experiments/reports/FINAL_BENCHMARK_REPORT.md, Table 1.", space_after=4)
add_table(
    ["Arm", "Description", "Replay J", "M-APR", "M-LTS", "M-LTS-0", "M-REVR", "M-VIOL", "Latency p95 (ms)"],
    [
        ["B0", "AlwaysAllow", "0.0000", "0.0000", "1.0000", "1.0000", "0.0000", "0 / 0", "0.006"],
        ["B1", "AlwaysDeny", "0.0000", "1.0000", "0.0000", "0.0000", "0.0000", "0 / 0", "0.008"],
        ["B2", "AlwaysReview", "0.0000", "1.0000", "1.0000", "0.0000", "1.0000", "0 / 0", "0.008"],
        ["B3", "Stateless Policy", "0.0000", "1.0000", "1.0000", "0.0000", "0.3333", "0 / 0", "0.851"],
        ["B4", "Action-Only Monitor", "0.0000", "1.0000", "1.0000", "0.0000", "0.3333", "0 / 0", "1.017"],
        ["B5", "Transcript Monitor", "0.0000", "1.0000", "1.0000", "0.0000", "0.3333", "0 / 0", "1.401"],
        ["B6", "Stateful Policy", "0.5000", "1.0000", "1.0000", "0.5000", "0.0833", "0 / 0", "1.337"],
        ["P1", "Hybrid Cascade", "0.5000", "1.0000", "1.0000", "0.5000", "0.0833", "0 / 0", "1.023"],
    ],
    col_widths=[0.5, 1.3, 0.6, 0.5, 0.5, 0.6, 0.6, 0.6, 0.8],
    font_size=8,
)

add_heading("B.2 Calibration Split Results (CAL, N = 8)", level=2)
add_table(
    ["Arm", "Replay J", "M-APR", "M-LTS", "M-LTS-0", "M-REVR", "M-VIOL", "Latency p95 (ms)"],
    [
        ["B0", "0.0000", "0.0000", "1.0000", "1.0000", "0.0000", "0 / 0", "0.006"],
        ["B1", "0.0000", "1.0000", "0.0000", "0.0000", "0.0000", "0 / 0", "0.005"],
        ["B2", "0.0000", "1.0000", "1.0000", "0.0000", "1.0000", "0 / 0", "0.013"],
        ["B3", "0.0000", "1.0000", "1.0000", "0.0000", "0.3333", "0 / 0", "1.020"],
        ["B4", "0.0000", "1.0000", "1.0000", "0.0000", "0.3333", "0 / 0", "1.152"],
        ["B5", "0.0000", "1.0000", "1.0000", "0.0000", "0.3333", "0 / 0", "1.059"],
        ["B6", "0.5000", "1.0000", "1.0000", "0.5000", "0.0833", "0 / 0", "1.096"],
        ["P1", "0.5000", "1.0000", "1.0000", "0.5000", "0.0833", "0 / 0", "1.066"],
    ],
    col_widths=[0.6, 0.7, 0.6, 0.6, 0.6, 0.7, 0.7, 0.8],
    font_size=8,
)

add_heading("B.3 Test-Novel Split Results (N = 4)", level=2)
add_table(
    ["Arm", "Replay J", "M-APR", "M-LTS", "M-LTS-0", "M-REVR", "M-VIOL", "Latency p95 (ms)"],
    [
        ["B0", "0.0000", "0.0000", "1.0000", "1.0000", "0.0000", "0 / 0", "0.018"],
        ["B1", "0.0000", "1.0000", "0.0000", "0.0000", "0.0000", "0 / 0", "0.015"],
        ["B2", "0.0000", "1.0000", "1.0000", "0.0000", "1.0000", "0 / 0", "0.026"],
        ["B3", "0.0000", "1.0000", "1.0000", "0.0000", "0.2500", "0 / 0", "1.341"],
        ["B4", "0.0000", "1.0000", "1.0000", "0.0000", "0.2500", "0 / 0", "1.462"],
        ["B5", "0.0000", "1.0000", "1.0000", "0.0000", "0.2500", "0 / 0", "1.293"],
        ["B6", "1.0000", "1.0000", "1.0000", "1.0000", "0.0000", "0 / 0", "1.709"],
        ["P1", "1.0000", "1.0000", "1.0000", "1.0000", "0.0000", "0 / 0", "0.936"],
    ],
    col_widths=[0.6, 0.7, 0.6, 0.6, 0.6, 0.7, 0.7, 0.8],
    font_size=8,
)

add_heading("B.4 Test Execution Summary", level=2)
add_body("Total tests: 415 passed, 0 failed, 0 skipped. Test duration: 10.87s. Test suites: unit (19 files), invariants (2 files), integration (2 files), experiments (7 files), property (1 file). FW-GATE satisfied: all T-INV-01…12 invariant tests pass.", space_after=8)

add_page_break()

# =====================================================================
# APPENDIX C: SECURITY INVARIANTS
# =====================================================================
add_heading("APPENDIX C: SECURITY INVARIANTS", level=1)
add_body("Twelve security invariants were specified in docs/01_THREAT_MODEL.md and verified across the test suite.", space_after=8)
add_table(
    ["ID", "Invariant", "Verification Method", "Status"],
    [
        ["INV-01", "State monotonicity and authenticity", "SHA-256 state-head chaining; T-STA tests", "VERIFIED"],
        ["INV-02", "Non-bypassable gateway", "Executor requires gateway token; T-EXE tests", "VERIFIED"],
        ["INV-03", "Policy precedence (PROHIBIT dominance)", "P-PROHIB exhaustive enumeration; T-DEC-001", "VERIFIED"],
        ["INV-04", "Review ticket HMAC binding", "Tokens bound to action hash + session ID", "VERIFIED"],
        ["INV-05", "Evidence verification & review revalidation", "Signatures required; state-head recheck on approval", "VERIFIED"],
        ["INV-06", "Fail-closed default", "Timeouts/malformed/exceptions → UNKNOWN/REVIEW", "VERIFIED"],
        ["INV-07", "Preimage resistance", "Tamper-evident hash construction; T-HASH tests", "VERIFIED"],
        ["INV-08", "Information barrier", "Zero label leakage to views/monitors; CI label-leak check", "VERIFIED"],
        ["INV-09", "Audit immutability", "Append-only hash-chained store; T-AUD tests", "VERIFIED"],
        ["INV-10", "Transcript sanitization", "Secrets/credentials redacted in monitor views", "VERIFIED"],
        ["INV-11", "Rollback protection", "Monotonic state progression enforced", "VERIFIED"],
        ["INV-12", "Deterministic equivalence", "Identical inputs → identical outputs; rerun bit-identical", "VERIFIED"],
    ],
    col_widths=[0.7, 2.2, 2.4, 1.0],
    font_size=8,
)
add_caption("Table C-1: Security Invariant Audit Summary (INV-01 to INV-12). All 12 verified.")

doc.add_paragraph()
add_body("End of Report", bold=True, align=WD_ALIGN_PARAGRAPH.CENTER, size=12)

# ---------------- Save ----------------
out_path = "AASF_FINAL_PROJECT_REPORT.docx"
doc.save(out_path)
print(f"Saved: {out_path}")
