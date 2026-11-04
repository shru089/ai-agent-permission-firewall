"""
AASF Project Report - Front Matter Generator.
Produces:
1. Cover Page
2. Certificate of Approval
3. University Approval Page
4. Student Declaration
5. Abstract (250-300 words)
6. Acknowledgement
7. Table of Contents
8. List of Figures
9. List of Tables
10. List of Abbreviations
"""

from docx import Document
from docx.shared import Pt, Inches, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from styles import NAVY, BLACK, CHARCOAL, add_p, add_page_break, set_cell_padding

def add_front_matter(doc: Document):
    # ---------------- 1. COVER PAGE ----------------
    p_univ = doc.add_paragraph()
    p_univ.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_univ.paragraph_format.space_before = Pt(36)
    p_univ.paragraph_format.space_after = Pt(4)
    run_u = p_univ.add_run("CHHATRAPATI SHIVAJI MAHARAJ UNIVERSITY\n")
    run_u.font.name = "Times New Roman"
    run_u.font.size = Pt(16)
    run_u.font.bold = True
    run_u.font.color.rgb = NAVY
    
    run_loc = p_univ.add_run("PANVEL, NAVI MUMBAI, MAHARASHTRA – 410206\n")
    run_loc.font.name = "Times New Roman"
    run_loc.font.size = Pt(11)
    run_loc.font.bold = True
    run_loc.font.color.rgb = CHARCOAL
    
    run_dept = p_univ.add_run("DEPARTMENT OF COMPUTER SCIENCE AND ENGINEERING")
    run_dept.font.name = "Times New Roman"
    run_dept.font.size = Pt(12)
    run_dept.font.bold = True
    run_dept.font.color.rgb = NAVY
    
    p_div = doc.add_paragraph()
    p_div.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_div.paragraph_format.space_before = Pt(8)
    p_div.paragraph_format.space_after = Pt(24)
    r_d = p_div.add_run("____________________________________________________________")
    r_d.font.color.rgb = NAVY

    p_proj = doc.add_paragraph()
    p_proj.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_proj.paragraph_format.space_before = Pt(12)
    p_proj.paragraph_format.space_after = Pt(12)
    
    run_rep = p_proj.add_run("A B.TECH CAPSTONE PROJECT REPORT ON\n\n")
    run_rep.font.name = "Times New Roman"
    run_rep.font.size = Pt(12)
    run_rep.font.color.rgb = CHARCOAL
    
    run_title = p_proj.add_run("ADAPTIVE AGENTIC SECURITY FIREWALL (AASF):\nRUNTIME RISK DETECTION AND MULTI-STEP ACCESS CONTROL FOR AUTONOMOUS AGENT WORKFLOWS\n")
    run_title.font.name = "Times New Roman"
    run_title.font.size = Pt(17)
    run_title.font.bold = True
    run_title.font.color.rgb = NAVY
    
    p_sub = doc.add_paragraph()
    p_sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_sub.paragraph_format.space_before = Pt(16)
    p_sub.paragraph_format.space_after = Pt(24)
    run_sub = p_sub.add_run("Submitted in partial fulfillment of the requirements\nfor the award of the degree of\n")
    run_sub.font.name = "Times New Roman"
    run_sub.font.size = Pt(11.5)
    run_sub.font.italic = True
    
    run_deg = p_sub.add_run("BACHELOR OF TECHNOLOGY\nIN COMPUTER SCIENCE AND ENGINEERING")
    run_deg.font.name = "Times New Roman"
    run_deg.font.size = Pt(13)
    run_deg.font.bold = True
    run_deg.font.color.rgb = BLACK
    
    p_team = doc.add_paragraph()
    p_team.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_team.paragraph_format.space_before = Pt(16)
    p_team.paragraph_format.space_after = Pt(24)
    
    run_by = p_team.add_run("Submitted By:\n")
    run_by.font.name = "Times New Roman"
    run_by.font.size = Pt(11)
    run_by.font.bold = True
    
    members = [
        ("SHRISHTI SINGH", "Roll No: F232984"),
        ("SNEHAL JAGTAP", "Roll No: F232951"),
        ("KARISHMA THAKUR", "Roll No: G242936"),
        ("AKSHAT KASURDE", "Roll No: F233339"),
    ]
    for name, roll in members:
        r_m = p_team.add_run(f"{name}  ({roll})\n")
        r_m.font.name = "Times New Roman"
        r_m.font.size = Pt(11)
        r_m.font.bold = True
        r_m.font.color.rgb = CHARCOAL
        
    p_guide = doc.add_paragraph()
    p_guide.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_guide.paragraph_format.space_before = Pt(12)
    p_guide.paragraph_format.space_after = Pt(24)
    
    run_ug = p_guide.add_run("Under the Esteemed Guidance of:\n")
    run_ug.font.name = "Times New Roman"
    run_ug.font.size = Pt(11)
    run_ug.font.bold = True
    
    run_gn = p_guide.add_run("[PROJECT GUIDE NAME - PLACEHOLDER]\n")
    run_gn.font.name = "Times New Roman"
    run_gn.font.size = Pt(12)
    run_gn.font.bold = True
    run_gn.font.color.rgb = NAVY
    
    run_gd = p_guide.add_run("Department of Computer Science and Engineering\nChhatrapati Shivaji Maharaj University, Panvel\n\nAcademic Year 2026–2027")
    run_gd.font.name = "Times New Roman"
    run_gd.font.size = Pt(11)
    
    add_page_break(doc)

    # ---------------- 2. CERTIFICATE ----------------
    p_cert_title = doc.add_paragraph()
    p_cert_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_cert_title.paragraph_format.space_before = Pt(24)
    p_cert_title.paragraph_format.space_after = Pt(18)
    r_ct = p_cert_title.add_run("DEPARTMENT OF COMPUTER SCIENCE AND ENGINEERING\nCHHATRAPATI SHIVAJI MAHARAJ UNIVERSITY, PANVEL")
    r_ct.font.name = "Times New Roman"
    r_ct.font.size = Pt(13)
    r_ct.font.bold = True
    r_ct.font.color.rgb = NAVY
    
    p_c_head = doc.add_paragraph()
    p_c_head.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_c_head.paragraph_format.space_before = Pt(12)
    p_c_head.paragraph_format.space_after = Pt(24)
    r_ch = p_c_head.add_run("CERTIFICATE OF APPROVAL")
    r_ch.font.name = "Times New Roman"
    r_ch.font.size = Pt(16)
    r_ch.font.bold = True
    r_ch.font.color.rgb = BLACK
    
    add_p(doc, "This is to certify that the B.Tech Capstone Project Report entitled “ADAPTIVE AGENTIC SECURITY FIREWALL (AASF): RUNTIME RISK DETECTION AND MULTI-STEP ACCESS CONTROL FOR AUTONOMOUS AGENT WORKFLOWS” is a bonafide work carried out by:")
    
    p_cand = doc.add_paragraph()
    p_cand.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_cand.paragraph_format.space_before = Pt(8)
    p_cand.paragraph_format.space_after = Pt(12)
    for name, roll in members:
        r = p_cand.add_run(f"• {name} (Roll No: {roll})\n")
        r.font.bold = True
        r.font.size = Pt(11.5)
        
    add_p(doc, "in partial fulfillment of the requirements for the award of the degree of Bachelor of Technology in Computer Science and Engineering from Chhatrapati Shivaji Maharaj University, Panvel during the academic year 2026–2027. It is further certified that all students have independently contributed to their designated research and engineering ownership modules and that the work has reached the required standards of technical excellence and academic rigor.")

    # Signature blocks
    p_sig = doc.add_paragraph()
    p_sig.paragraph_format.space_before = Pt(48)
    p_sig.paragraph_format.space_after = Pt(12)
    
    table_sig = doc.add_table(rows=2, cols=3)
    table_sig.autofit = True
    sigs = [
        ("_____________________\n[Project Guide Name]\nProject Guide\nDept. of CSE", 0),
        ("_____________________\n[HOD Name]\nHead of Department\nDept. of CSE", 1),
        ("_____________________\n[Dean/Principal Name]\nDean / Principal\nFaculty of Engg. & Tech.", 2)
    ]
    for text, col_idx in sigs:
        cell = table_sig.cell(0, col_idx)
        p = cell.paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = p.add_run(text)
        run.font.name = "Times New Roman"
        run.font.size = Pt(10)
        
    add_page_break(doc)

    # ---------------- 3. APPROVAL PAGE ----------------
    p_app_title = doc.add_paragraph()
    p_app_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_app_title.paragraph_format.space_before = Pt(24)
    p_app_title.paragraph_format.space_after = Pt(24)
    r_at = p_app_title.add_run("UNIVERSITY PROJECT APPROVAL PAGE")
    r_at.font.name = "Times New Roman"
    r_at.font.size = Pt(16)
    r_at.font.bold = True
    r_at.font.color.rgb = NAVY

    add_p(doc, "This B.Tech Capstone Project Report entitled “ADAPTIVE AGENTIC SECURITY FIREWALL (AASF): RUNTIME RISK DETECTION AND MULTI-STEP ACCESS CONTROL FOR AUTONOMOUS AGENT WORKFLOWS” submitted by Shrishti Singh (F232984), Snehal Jagtap (F232951), Karishma Thakur (G242936), and Akshat Kasurde (F233339) is approved for the award of the degree of Bachelor of Technology in Computer Science and Engineering.")
    
    p_exam = doc.add_paragraph()
    p_exam.paragraph_format.space_before = Pt(64)
    p_exam.paragraph_format.space_after = Pt(24)
    
    table_exam = doc.add_table(rows=1, cols=2)
    table_exam.autofit = True
    
    c1 = table_exam.cell(0, 0)
    p1 = c1.paragraphs[0]
    p1.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r1 = p1.add_run("_____________________________\nInternal Examiner\n\nName: _______________________\nDate: _______________________")
    r1.font.size = Pt(10.5)
    
    c2 = table_exam.cell(0, 1)
    p2 = c2.paragraphs[0]
    p2.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r2 = p2.add_run("_____________________________\nExternal Examiner\n\nName: _______________________\nDate: _______________________")
    r2.font.size = Pt(10.5)
    
    p_seal = doc.add_paragraph()
    p_seal.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_seal.paragraph_format.space_before = Pt(48)
    r_seal = p_seal.add_run("Institutional Seal:\n\n\n[ SEAL ]")
    r_seal.font.italic = True
    r_seal.font.color.rgb = CHARCOAL
    
    add_page_break(doc)

    # ---------------- 4. DECLARATION ----------------
    p_dec_title = doc.add_paragraph()
    p_dec_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_dec_title.paragraph_format.space_before = Pt(24)
    p_dec_title.paragraph_format.space_after = Pt(24)
    r_dt = p_dec_title.add_run("STUDENT DECLARATION")
    r_dt.font.name = "Times New Roman"
    r_dt.font.size = Pt(16)
    r_dt.font.bold = True
    r_dt.font.color.rgb = NAVY

    add_p(doc, "We hereby declare that the capstone project work entitled “ADAPTIVE AGENTIC SECURITY FIREWALL (AASF): RUNTIME RISK DETECTION AND MULTI-STEP ACCESS CONTROL FOR AUTONOMOUS AGENT WORKFLOWS” is an authentic record of our own original work conducted in the Department of Computer Science and Engineering at Chhatrapati Shivaji Maharaj University, Panvel, under the supervision of our Project Guide.")
    
    add_p(doc, "We confirm that this report has not been submitted previously to this or any other university or institution for the award of any degree, diploma, fellowship, or other academic recognition. All sources of information, external libraries, datasets, and peer-reviewed literature have been duly acknowledged and cited according to academic standards.")
    
    add_p(doc, "We further affirm that the report's empirical claims are attributed to repository artifacts where available. The cited test run verifies the executed test suite; it does not establish that every evaluation result can be regenerated from a clean checkout.")

    p_sig_s = doc.add_paragraph()
    p_sig_s.paragraph_format.space_before = Pt(48)
    
    table_s = doc.add_table(rows=2, cols=2)
    table_s.autofit = True
    s_cells = [
        ("_____________________________\nSHRISHTI SINGH\nRoll No: F232984\nDate: ____________", 0, 0),
        ("_____________________________\nSNEHAL JAGTAP\nRoll No: F232951\nDate: ____________", 0, 1),
        ("_____________________________\nKARISHMA THAKUR\nRoll No: G242936\nDate: ____________", 1, 0),
        ("_____________________________\nAKSHAT KASURDE\nRoll No: F233339\nDate: ____________", 1, 1),
    ]
    for text, r_idx, c_idx in s_cells:
        cell = table_s.cell(r_idx, c_idx)
        set_cell_padding(cell, top=100, bottom=100, left=80, right=80)
        p = cell.paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = p.add_run(text)
        run.font.name = "Times New Roman"
        run.font.size = Pt(10)
        
    add_page_break(doc)

    # ---------------- 5. ABSTRACT ----------------
    p_abs_title = doc.add_paragraph()
    p_abs_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_abs_title.paragraph_format.space_before = Pt(24)
    p_abs_title.paragraph_format.space_after = Pt(18)
    r_ab = p_abs_title.add_run("ABSTRACT")
    r_ab.font.name = "Times New Roman"
    r_ab.font.size = Pt(16)
    r_ab.font.bold = True
    r_ab.font.color.rgb = NAVY

    # Exactly 272 words (within the 250-300 range)
    abstract_text = (
        "Autonomous artificial intelligence (AI) agents driven by large language models (LLMs) are increasingly deployed "
        "to orchestrate complex, multi-step workflows across enterprise software systems, external APIs, and sensitive data stores. "
        "However, current security mechanisms predominantly rely either on static, single-step permission policies or unconstrained "
        "human-in-the-loop review queues. These approaches fail to defend against emergent threats such as multi-step context manipulation, "
        "confused-deputy data exfiltration, and unauthorized privilege drift, while review requirements may add operational workload. "
        "This project presents the Adaptive Agentic Security Firewall (AASF), an in-process security mediation prototype. AASF includes "
        "three primary technical innovations: (1) a deterministic, monotonic state-folding engine (Phi) that cryptographically accumulates "
        "session history; (2) a three-valued policy engine coupled with a pure decision combinator (Delta), designed around twelve "
        "security invariants (INV-01 to INV-12); and (3) an advisory cascade that integrates rule-based "
        "heuristics and offline LLM monitors without granting advisory models execution authority. The system was empirically evaluated "
        "across four pre-registered canonical dataset splits (DEV, CAL, TEST-IN, and TEST-NOVEL) under strict action-history invariance. "
        "The DEV manipulation-check artifact reports Youden's J = 0.0 for B3 and B4. In the benchmark summary, B3/B4 report J = 0.0000 on "
        "TEST-IN and TEST-NOVEL, while B6/P1 report J = 0.5000 on TEST-IN and 1.0000 on TEST-NOVEL. On both held-out splits, B6 and P1 "
        "each report M-APR = 1.0000. Compared with B3, B6 review rate decreased from 0.3333 to 0.0833 on TEST-IN (75%) and from 0.2500 "
        "to 0.0000 on TEST-NOVEL (100%). P1 arm-level p95 evaluator latency was 1.023 ms on TEST-IN and 0.936 ms on TEST-NOVEL. These results are "
        "specific to the evaluated arms and splits. H2 and H3 are not verified against all frozen criteria. See Section 8.10 for the full H5 latency limitation."
    )
    add_p(doc, abstract_text)
    
    p_kw = doc.add_paragraph()
    p_kw.paragraph_format.space_before = Pt(12)
    p_kw.paragraph_format.space_after = Pt(6)
    r_kw_title = p_kw.add_run("Keywords: ")
    r_kw_title.font.bold = True
    r_kw_title.font.color.rgb = NAVY
    r_kw = p_kw.add_run("Autonomous AI Agents, Runtime Risk Detection, Multi-Step Access Control, Security Invariants, State Folding, Decision Combinator, Advisory Cascades, Cryptographic Audit Trail.")
    r_kw.font.italic = True
    
    add_page_break(doc)

    # ---------------- 6. ACKNOWLEDGEMENTS ----------------
    p_ack_title = doc.add_paragraph()
    p_ack_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_ack_title.paragraph_format.space_before = Pt(24)
    p_ack_title.paragraph_format.space_after = Pt(18)
    r_ack = p_ack_title.add_run("ACKNOWLEDGEMENTS")
    r_ack.font.name = "Times New Roman"
    r_ack.font.size = Pt(16)
    r_ack.font.bold = True
    r_ack.font.color.rgb = NAVY

    add_p(doc, "We express our deepest sense of gratitude and respect to our Project Guide, [Project Guide Name], Department of Computer Science and Engineering, Chhatrapati Shivaji Maharaj University, Panvel, for their invaluable mentorship, technical guidance, critical insights, and relentless encouragement throughout the conception, formalization, and execution of this project.")
    
    add_p(doc, "We extend our sincere thanks to the Head of the Department of Computer Science and Engineering, for providing the necessary computational facilities, state-of-the-art laboratory infrastructure, and an academically stimulating research environment that enabled us to conduct rigorous empirical benchmarks.")
    
    add_p(doc, "We also express our heartfelt thanks to the Hon’ble Vice Chancellor, Registrar, and Dean of the Faculty of Engineering and Technology, Chhatrapati Shivaji Maharaj University, for their continuous support and institutional resources.")
    
    add_p(doc, "Finally, we owe our deepest gratitude to our parents, family members, and peers for their constant encouragement, moral support, and patience throughout the duration of this demanding capstone endeavor.")
    
    add_page_break(doc)

    # ---------------- 7. TABLE OF CONTENTS ----------------
    p_toc_title = doc.add_paragraph()
    p_toc_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_toc_title.paragraph_format.space_before = Pt(24)
    p_toc_title.paragraph_format.space_after = Pt(18)
    r_toc = p_toc_title.add_run("TABLE OF CONTENTS")
    r_toc.font.name = "Times New Roman"
    r_toc.font.size = Pt(16)
    r_toc.font.bold = True
    r_toc.font.color.rgb = NAVY

    toc_entries = [
        ("Certificate of Approval", "ii"),
        ("University Approval Page", "iii"),
        ("Student Declaration", "iv"),
        ("Abstract", "v"),
        ("Acknowledgements", "vi"),
        ("List of Figures", "viii"),
        ("List of Tables", "ix"),
        ("List of Abbreviations", "x"),
        ("CHAPTER 1: INTRODUCTION", "1"),
        ("   1.1 Background and Motivation", "1"),
        ("   1.2 Introduction to Autonomous AI Agents", "3"),
        ("   1.3 Security Challenges in Agentic Systems", "5"),
        ("   1.4 Problem Statement", "7"),
        ("   1.5 Motivation and Industry Relevance", "8"),
        ("   1.6 Project Objectives", "9"),
        ("   1.7 Project Scope and System Boundaries", "10"),
        ("   1.8 Proposed Solution: The AASF Framework", "12"),
        ("   1.9 Organization of the Report", "13"),
        ("CHAPTER 2: LITERATURE REVIEW", "15"),
        ("   2.1 Introduction", "15"),
        ("   2.2 Existing Security Approaches", "16"),
        ("   2.3 Review of Relevant Research Papers", "18"),
        ("   2.4 Comparative Analysis Matrix", "22"),
        ("   2.5 Research Gaps in Contemporary Frameworks", "24"),
        ("   2.6 Research Contributions of AASF", "25"),
        ("   2.7 Summary", "26"),
        ("CHAPTER 3: SYSTEM REQUIREMENT SPECIFICATION (SRS)", "27"),
        ("   3.1 Introduction", "27"),
        ("   3.2 Functional Requirements (FR-01 to FR-12)", "28"),
        ("   3.3 Non-Functional Requirements (NFR-01 to NFR-08)", "32"),
        ("   3.4 Hardware Requirements", "34"),
        ("   3.5 Software Requirements and Dependencies", "35"),
        ("   3.6 Development Environment and Standards", "36"),
        ("   3.7 Technology Stack Justification", "37"),
        ("   3.8 Security Requirements and Invariant Catalog", "38"),
        ("   3.9 Constraints and Assumptions", "41"),
        ("CHAPTER 4: PLAN OF PROJECT", "43"),
        ("   4.1 Project Planning Overview", "43"),
        ("   4.2 Development Methodology (Test-Driven Invariant Engineering)", "44"),
        ("   4.3 Research Methodology and Protocol Pre-registration", "46"),
        ("   4.4 Project Phases and Milestones", "47"),
        ("   4.5 Work Breakdown Structure (WBS)", "49"),
        ("   4.6 Timeline and Gantt Chart", "51"),
        ("   4.7 Team Ownership and Responsibility Matrix", "53"),
        ("   4.8 Risk Management and Mitigation Strategies", "55"),
        ("CHAPTER 5: PROJECT ANALYSIS", "57"),
        ("   5.1 Existing System Analysis", "57"),
        ("   5.2 Critical Limitations of Existing Systems", "58"),
        ("   5.3 Proposed System Architecture and Advantages", "60"),
        ("   5.4 Multidimensional Feasibility Analysis", "62"),
        ("   5.5 Use Case Analysis and Actor Modeling", "64"),
        ("   5.6 Functional Decomposition", "66"),
        ("   5.7 Data Flow Analysis (Level 0 DFD)", "68"),
        ("   5.8 System Workflow and Request Lifecycle", "70"),
        ("CHAPTER 6: PROJECT DESIGN", "72"),
        ("   6.1 Overall System Architecture", "72"),
        ("   6.2 Architectural Design Principles", "74"),
        ("   6.3 Detailed Component and Module Design", "76"),
        ("   6.4 Data Flow Diagrams (Level 1 DFD)", "80"),
        ("   6.5 UML Class Diagram", "82"),
        ("   6.6 UML Sequence Diagram (Authorization Pipeline)", "84"),
        ("   6.7 UML Activity Diagram (Interception and Cascading)", "86"),
        ("   6.8 State Fold Engine (Phi) and Hash-Chained State Design", "88"),
        ("   6.9 Security Design: Token Lifecycle and Isolation Views", "90"),
        ("   6.10 Decision Combinator Architecture (Delta)", "92"),
        ("CHAPTER 7: IMPLEMENTATION", "94"),
        ("   7.1 Development Environment and Package Structure", "94"),
        ("   7.2 Repository Organization and Clean Architecture", "96"),
        ("   7.3 Implementation Architecture and Interception Boundary", "98"),
        ("   7.4 Runtime Firewall Core Orchestrator", "100"),
        ("   7.5 Stateful Policy Engine and Three-Valued Logic", "102"),
        ("   7.6 Advisory Monitor Interface and Rejection Cascade", "104"),
        ("   7.7 Decision Combinator Implementation", "106"),
        ("   7.8 Human Oversight and Revalidation Service", "108"),
        ("   7.9 Execution Token Store and Controlled Executor", "110"),
        ("   7.10 Deterministic State Folding Engine", "112"),
        ("   7.11 Tamper-Evident Hash-Chained Audit Store", "114"),
        ("   7.12 Implementation Traceability of Invariants INV-01 to INV-12", "116"),
        ("   7.13 Technical Implementation Highlights and Code Snippets", "118"),
        ("CHAPTER 8: RESULT ANALYSIS AND DISCUSSION", "122"),
        ("   8.1 Experimental Setup and Pre-registered Protocol", "122"),
        ("   8.2 Testing Methodology and Test Suite Verification", "124"),
        ("   8.3 Functional Verification and Unit Test Distribution", "126"),
        ("   8.4 Security and Invariant Regression Testing", "128"),
        ("   8.5 Empirical Benchmark Results across Experimental Arms", "130"),
        ("   8.6 Runtime Latency and Performance Overhead Evaluation", "134"),
        ("   8.7 Calibration Analysis on Validation Split", "136"),
        ("   8.9 Comparative Baseline Analysis and Confusion Matrices", "140"),
        ("   8.10 Pre-registered Hypothesis Testing (H1 to H5)", "142"),
        ("   8.11 Limitations and Threats to Validity", "145"),
        ("CHAPTER 9: CONCLUSION AND FUTURE SCOPE", "147"),
        ("   9.1 Project Summary", "147"),
        ("   9.2 Fulfillment of Project Objectives", "148"),
        ("   9.3 Core Research Contributions", "150"),
        ("   9.4 Engineering and Technical Contributions", "151"),
        ("   9.5 Encountered Limitations", "152"),
        ("   9.6 Future Scope and Extension Roadmaps", "153"),
        ("   9.7 Final Concluding Remarks", "155"),
        ("REFERENCES / BIBLIOGRAPHY", "156"),
        ("APPENDIX I: RESEARCH MANUSCRIPTS", "160"),
        ("APPENDIX II: MANUSCRIPT ABSTRACT", "162"),
        ("APPENDIX III: SIMILARITY VERIFICATION STATUS", "163"),
        ("APPENDIX IV: FORMAL SPECIFICATIONS OF SECURITY INVARIANTS", "164"),
        ("APPENDIX V: CRYPTOGRAPHIC BENCHMARK MANIFESTS", "168"),
    ]
    
    t_toc = doc.add_table(rows=len(toc_entries), cols=2)
    t_toc.autofit = False
    for i, (title, page) in enumerate(toc_entries):
        row = t_toc.rows[i]
        c0, c1 = row.cells[0], row.cells[1]
        c0.width = Inches(5.3)
        c1.width = Inches(0.7)
        set_cell_padding(c0, top=20, bottom=20, left=40, right=40)
        set_cell_padding(c1, top=20, bottom=20, left=40, right=40)
        
        p0 = c0.paragraphs[0]
        p0.alignment = WD_ALIGN_PARAGRAPH.LEFT
        p0.paragraph_format.line_spacing = 1.15
        p0.paragraph_format.space_after = Pt(1)
        r0 = p0.add_run(title)
        r0.font.name = "Times New Roman"
        r0.font.size = Pt(10)
        if title.startswith("CHAPTER") or title in ["REFERENCES / BIBLIOGRAPHY", "ABSTRACT"]:
            r0.font.bold = True
            
        p1 = c1.paragraphs[0]
        p1.alignment = WD_ALIGN_PARAGRAPH.RIGHT
        p1.paragraph_format.line_spacing = 1.15
        p1.paragraph_format.space_after = Pt(1)
        r1 = p1.add_run(page)
        r1.font.name = "Times New Roman"
        r1.font.size = Pt(10)
        if title.startswith("CHAPTER") or title in ["REFERENCES / BIBLIOGRAPHY", "ABSTRACT"]:
            r1.font.bold = True
            
    add_page_break(doc)

    # ---------------- 8. LIST OF FIGURES ----------------
    p_lof_title = doc.add_paragraph()
    p_lof_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_lof_title.paragraph_format.space_before = Pt(24)
    p_lof_title.paragraph_format.space_after = Pt(18)
    r_lof = p_lof_title.add_run("LIST OF FIGURES")
    r_lof.font.name = "Times New Roman"
    r_lof.font.size = Pt(16)
    r_lof.font.bold = True
    r_lof.font.color.rgb = NAVY

    lof_entries = [
        ("Figure 4.1", "Project Work Breakdown Structure and Timeline Gantt Chart", "52"),
        ("Figure 5.1", "Comprehensive AASF System Use Case Diagram with Multi-Actor Modeling", "65"),
        ("Figure 5.2", "Context-Level Data Flow Diagram (DFD Level 0) of In-Process Interception", "69"),
        ("Figure 6.1", "Overall Multi-Tiered AASF System Architecture", "73"),
        ("Figure 6.2", "End-to-End Agent-to-Firewall Interception and Execution Pipeline", "75"),
        ("Figure 6.3", "Decision Combinator Flowchart and Strict Security Invariant Evaluation", "79"),
        ("Figure 6.4", "Monotonic State Fold (Phi) and Hash-Chained Cryptographic Architecture", "81"),
        ("Figure 6.5", "UML Sequence Diagram: Complete Action Request Authorization Lifecycle", "85"),
        ("Figure 6.6", "Detailed Level 1 Data Flow Diagram (DFD Level 1) for Core Subsystems", "87"),
        ("Figure 6.7", "UML Class Diagram of FirewallCore, StateEngine, and Decision Modules", "89"),
        ("Figure 6.8", "MonitorView Information Isolation Barrier (INV-10 Redaction Enforcement)", "91"),
        ("Figure 6.9", "Single-Use Cryptographic Execution Token Lifecycle and Transition Model", "93"),
        ("Figure 6.10", "UML Activity Diagram for Dynamic Advisory Cascades and Fallback Routing", "95"),
        ("Figure 8.1", "Attack Prevention Rate (APR) vs. Legitimate Task Success (LTS) on TEST-IN", "131"),
        ("Figure 8.2", "Human Review Burden Reduction across Evaluated System Configurations", "133"),
        ("Figure 8.3", "Confusion Matrix Heatmaps on Critical Scenarios for B0, B1, B3, and AASF", "141"),
        ("Figure 8.4", "Youden’s J Statistic for Multi-Step History Manipulation across Splits (H1)", "135"),
        ("Figure 8.5", "Uninterrupted Legitimate Task Success (M-LTS-0) Tradeoff Comparison (H2)", "137"),
    ]
    
    t_lof = doc.add_table(rows=len(lof_entries), cols=3)
    t_lof.autofit = False
    for i, (f_num, f_cap, f_page) in enumerate(lof_entries):
        row = t_lof.rows[i]
        c0, c1, c2 = row.cells[0], row.cells[1], row.cells[2]
        c0.width = Inches(1.2)
        c1.width = Inches(4.2)
        c2.width = Inches(0.6)
        set_cell_padding(c0, top=20, bottom=20, left=30, right=30)
        set_cell_padding(c1, top=20, bottom=20, left=30, right=30)
        set_cell_padding(c2, top=20, bottom=20, left=30, right=30)
        
        p0 = c0.paragraphs[0]
        p0.paragraph_format.line_spacing = 1.15
        r0 = p0.add_run(f_num)
        r0.font.bold = True
        r0.font.size = Pt(9.5)
        
        p1 = c1.paragraphs[0]
        p1.paragraph_format.line_spacing = 1.15
        r1 = p1.add_run(f_cap)
        r1.font.size = Pt(9.5)
        
        p2 = c2.paragraphs[0]
        p2.alignment = WD_ALIGN_PARAGRAPH.RIGHT
        p2.paragraph_format.line_spacing = 1.15
        r2 = p2.add_run(f_page)
        r2.font.size = Pt(9.5)
        
    add_page_break(doc)

    # ---------------- 9. LIST OF TABLES ----------------
    p_lot_title = doc.add_paragraph()
    p_lot_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_lot_title.paragraph_format.space_before = Pt(24)
    p_lot_title.paragraph_format.space_after = Pt(18)
    r_lot = p_lot_title.add_run("LIST OF TABLES")
    r_lot.font.name = "Times New Roman"
    r_lot.font.size = Pt(16)
    r_lot.font.bold = True
    r_lot.font.color.rgb = NAVY

    lot_entries = [
        ("Table 2.1", "Comparative Analysis Matrix of Agent Security Frameworks vs. AASF", "23"),
        ("Table 3.1", "Technical Dependencies, Cryptographic Standards, and Tooling Stack", "37"),
        ("Table 3.2", "Formal Catalog of AASF Core Security Invariants (INV-01 to INV-12)", "39"),
        ("Table 4.1", "Work Breakdown Structure (WBS) and Phase-Wise Deliverables", "50"),
        ("Table 4.2", "Team Responsibilities and Engineering Ownership Matrix", "54"),
        ("Table 4.3", "Project Risk Assessment, Probability, Impact, and Mitigation Strategies", "56"),
        ("Table 5.1", "Comparative Feature Matrix: Conventional Controls vs. Proposed AASF", "61"),
        ("Table 7.1", "Repository Package Organization and Subsystem Directory Mapping", "97"),
        ("Table 7.2", "Implementation Mapping of Mathematical Security Invariants in Code", "117"),
        ("Table 8.1", "Deterministic Canonical Dataset Splits and Action-D Invariance Profile", "123"),
        ("Table 8.2", "Automated Test Execution Summary", "127"),
        ("Table 8.3", "Empirical Evaluation Metrics across 8 Experimental Arms on TEST-IN Split", "131"),
        ("Table 8.4", "Calibration Split (CAL, N=8) Decision Threshold Optimization Outcomes", "136"),
        ("Table 8.5", "Measured Values for Pre-Registered Hypotheses (H1 through H5)", "143"),
    ]
    
    t_lot = doc.add_table(rows=len(lot_entries), cols=3)
    t_lot.autofit = False
    for i, (t_num, t_cap, t_page) in enumerate(lot_entries):
        row = t_lot.rows[i]
        c0, c1, c2 = row.cells[0], row.cells[1], row.cells[2]
        c0.width = Inches(1.2)
        c1.width = Inches(4.2)
        c2.width = Inches(0.6)
        set_cell_padding(c0, top=20, bottom=20, left=30, right=30)
        set_cell_padding(c1, top=20, bottom=20, left=30, right=30)
        set_cell_padding(c2, top=20, bottom=20, left=30, right=30)
        
        p0 = c0.paragraphs[0]
        p0.paragraph_format.line_spacing = 1.15
        r0 = p0.add_run(t_num)
        r0.font.bold = True
        r0.font.size = Pt(9.5)
        
        p1 = c1.paragraphs[0]
        p1.paragraph_format.line_spacing = 1.15
        r1 = p1.add_run(t_cap)
        r1.font.size = Pt(9.5)
        
        p2 = c2.paragraphs[0]
        p2.alignment = WD_ALIGN_PARAGRAPH.RIGHT
        p2.paragraph_format.line_spacing = 1.15
        r2 = p2.add_run(t_page)
        r2.font.size = Pt(9.5)
        
    add_page_break(doc)

    # ---------------- 10. LIST OF ABBREVIATIONS ----------------
    p_ab_title = doc.add_paragraph()
    p_ab_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_ab_title.paragraph_format.space_before = Pt(24)
    p_ab_title.paragraph_format.space_after = Pt(18)
    r_ab = p_ab_title.add_run("LIST OF ABBREVIATIONS")
    r_ab.font.name = "Times New Roman"
    r_ab.font.size = Pt(16)
    r_ab.font.bold = True
    r_ab.font.color.rgb = NAVY

    abbreviations = [
        ("AASF", "Adaptive Agentic Security Firewall"),
        ("ABAC", "Attribute-Based Access Control"),
        ("AI", "Artificial Intelligence"),
        ("API", "Application Programming Interface"),
        ("APR", "Attack Prevention Rate"),
        ("ASR", "Attack Success Rate"),
        ("CAL", "Calibration Split (Dataset)"),
        ("CI/CD", "Continuous Integration / Continuous Deployment"),
        ("CSMU", "Chhatrapati Shivaji Maharaj University"),
        ("DFD", "Data Flow Diagram"),
        ("FNR", "False Negative Rate"),
        ("FPR", "False Positive Rate"),
        ("HMAC", "Hash-based Message Authentication Code"),
        ("HOD", "Head of the Department"),
        ("IEEE", "Institute of Electrical and Electronics Engineers"),
        ("INV", "Security Invariant"),
        ("JSON", "JavaScript Object Notation"),
        ("LLM", "Large Language Model"),
        ("LTS", "Legitimate Task Success"),
        ("NFR", "Non-Functional Requirement"),
        ("OS", "Operating System"),
        ("RBAC", "Role-Based Access Control"),
        ("REST", "Representational State Transfer"),
        ("SHA", "Secure Hash Algorithm"),
        ("SLA", "Service Level Agreement"),
        ("SRS", "System Requirement Specification"),
        ("TDD", "Test-Driven Development"),
        ("UML", "Unified Modeling Language"),
        ("URI", "Uniform Resource Identifier"),
        ("WBS", "Work Breakdown Structure"),
    ]
    
    t_ab = doc.add_table(rows=len(abbreviations), cols=2)
    t_ab.autofit = False
    for i, (short_form, full_form) in enumerate(abbreviations):
        row = t_ab.rows[i]
        c0, c1 = row.cells[0], row.cells[1]
        c0.width = Inches(1.5)
        c1.width = Inches(4.5)
        set_cell_padding(c0, top=15, bottom=15, left=30, right=30)
        set_cell_padding(c1, top=15, bottom=15, left=30, right=30)
        
        p0 = c0.paragraphs[0]
        p0.paragraph_format.line_spacing = 1.15
        r0 = p0.add_run(short_form)
        r0.font.bold = True
        r0.font.size = Pt(9.5)
        r0.font.color.rgb = NAVY
        
        p1 = c1.paragraphs[0]
        p1.paragraph_format.line_spacing = 1.15
        r1 = p1.add_run(full_form)
        r1.font.size = Pt(9.5)
        
    add_page_break(doc)
