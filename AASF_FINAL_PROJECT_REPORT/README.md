# AASF Final Project Report Delivery Package

**Project Title:** Adaptive Agentic Security Firewall (AASF): Runtime Risk Detection and Multi-Step Access Control for Autonomous Agent Workflows  
**Institution:** Chhatrapati Shivaji Maharaj University (CSMU), Panvel  
**Department:** Department of Computer Science and Engineering  
**Degree:** Bachelor of Technology in Computer Science and Engineering  
**Academic Year:** 2026–2027  

---

## 1. Package Contents and Directory Structure

This directory (`AASF_FINAL_PROJECT_REPORT/`) contains the complete final-year B.Tech capstone project documentation, experimental visualizations, technical architecture diagrams, and academic verification audits:

```text
AASF_FINAL_PROJECT_REPORT/
├── AASF_Final_Project_Report.docx       # Complete, editable Word document (A4, CSMU template)
├── AASF_Final_Project_Report.pdf        # Rendered PDF document with embedded high-res graphics
├── README.md                            # Package overview and quick start guide
├── REPORT_VERIFICATION.md               # Compliance checklist against academic standards
├── IMPLEMENTATION_TRACEABILITY.md       # Traceability matrix mapping claims to code and tests
├── FORMATTING_AUDIT.md                  # Audit of margins, font styles, and template conformance
├── MISSING_INFORMATION.md               # Official placeholders for institutional signatures
├── diagrams/                            # High-resolution (300 DPI) technical system diagrams
│   ├── fig4_1_project_gantt_chart.png
│   ├── fig5_1_system_use_case_diagram.png
│   ├── fig6_1_overall_aasf_architecture.png
│   ├── fig6_2_agent_execution_pipeline.png
│   ├── fig6_3_decision_combinator_flowchart.png
│   ├── fig6_4_hash_chained_state_architecture.png
│   ├── fig6_5_uml_sequence_diagram.png
│   ├── fig6_6_dfd_level_0.png
│   ├── fig6_7_uml_class_diagram.png
│   ├── fig6_8_monitorview_isolation.png
│   ├── fig6_9_token_lifecycle.png
│   ├── fig6_10_dfd_level_1.png
│   └── fig6_11_uml_activity_diagram.png
└── charts/                              # High-resolution (300 DPI) empirical benchmark charts
    ├── chart1_attack_prevention_vs_task_success.png
    ├── chart2_human_review_burden_reduction.png
    ├── chart3_youden_j_history_manipulation.png
    ├── chart4_uninterrupted_task_success.png
    ├── chart5_decision_latency_distribution.png
    ├── chart6_confusion_matrix_dev.png
    ├── chart7_test_suite_breakdown.png
    └── chart8_ablation_history_windows.png
```

---

## 2. Report Overview

The report consists of **9 complete chapters**, formal **Front Matter**, complete **IEEE References**, and **5 Technical Appendices**:

1. **Front Matter:** Cover Page, Certificate of Approval, University Approval Page, Student Declaration, Abstract (272 words), Acknowledgements, Table of Contents, List of Figures (21 figures), List of Tables (15 tables), and List of Abbreviations.
2. **Chapter 1: Introduction:** Background, Agentic Systems, Security Challenges, Problem Statement, Objectives, Scope, and Proposed Solution.
3. **Chapter 2: Literature Review:** Existing Security Approaches, Paper Reviews (ToolSafe, StepGuard, TraceSafe, Schneider, P1–P4), Comparative Matrix (Table 2.1), and Research Gaps.
4. **Chapter 3: System Requirement Specification:** FR-01 to FR-12, NFR-01 to NFR-08, Hardware/Software, Tech Stack (Table 3.1), Invariant Catalog (INV-01 to INV-12), and Assumptions.
5. **Chapter 4: Plan of Project:** TDIE Methodology, Protocol Pre-registration (PREREG-001), 9 Phases, WBS (Table 4.1), Gantt Chart (Fig 4.1), Team Responsibilities (Table 4.2), and Risk Matrix (Table 4.3).
6. **Chapter 5: Project Analysis:** Existing vs Proposed (Table 5.1), Feasibility Analysis, Use Case Diagram (Fig 5.1), Functional Decomposition, Context DFD Level 0 (Fig 5.2), and Request Lifecycle.
7. **Chapter 6: Project Design:** Multi-Tier Architecture (Fig 6.1), Principles, Component Design, DFD Level 1 (Fig 6.2), UML Class Diagram (Fig 6.3), UML Sequence Diagram (Fig 6.4), UML Activity Diagram (Fig 6.5), State Fold Architecture (Fig 6.6), MonitorView Isolation (Fig 6.7), Token Lifecycle (Fig 6.8), and Combinator Flowchart (Fig 6.9).
8. **Chapter 7: Implementation:** Environment, Repository Structure (Table 7.1), FirewallCore, PolicyEngine, Advisory Cascades, Decision Combinator, ReviewService, TokenStore, StateEngine, AuditStore, Invariant Traceability (Table 7.2), and Code Snippets.
9. **Chapter 8: Result Analysis and Discussion:** Experimental Splits (Table 8.1), 415 Test Verification (Table 8.2, Fig 8.1), TEST-IN Evaluation (Table 8.3, Figs 8.2 & 8.3), Latency Distribution (Fig 8.4), CAL Split Tuning (Table 8.4), History Window Ablations (Table 8.5, Fig 8.5), Confusion Matrices (Fig 8.6), Youden's J (Fig 8.7), Uninterrupted Success (Fig 8.8), Hypotheses Outcomes (Table 8.6, H1–H5), and Threats to Validity.
10. **Chapter 9: Conclusion and Future Scope:** Summary, Objectives Achieved, Research Contributions, Engineering Contributions, Limitations, and Future Extension Roadmaps.
11. **Back Matter & Appendices:** Full IEEE References (22 citations), Appendix I (Research Publications P1–P4), Appendix II (Published Paper Abstract), Appendix III (Plagiarism Report Placeholder), Appendix IV (Formal Invariant Specifications), and Appendix V (Cryptographic Manifests).

---

## 3. Engineering Team & Technical Subsystem Ownership

| Student Researcher | Roll Number | Subsystem Ownership | Key Academic Deliverable |
|---|---|---|---|
| **Shrishti Singh** | `F232984` | AI/ML & AI Risk/Threat Detection | Advisory Cascades, Prompt Injection Modeling, Hypothesis H1/H2 Evaluation (`[P1]`) |
| **Snehal Jagtap** | `F232951` | Full-Stack & Human Oversight Platform | ReviewService Ticketing, Dynamic Oversight Queue, Reviewer Fatigue Reduction (`[P4]`) |
| **Karishma Thakur** | `G242936` | Permission & Dynamic Policy Engine | Three-Valued PolicyEngine, Stateful ABAC Lattice, Dynamic Taint Tracking (`[P2]`) |
| **Akshat Kasurde** | `F233339` | Runtime Firewall & Agent Execution | FirewallCore Interception, ControlledExecutor, Single-Use TokenStore, Fast-Path (`[P3]`) |

---

## 4. Verification and Reproduction

To recompile the report or verify the codebase locally:

```bash
# 1. Run complete automated test suite (415 passing tests)
pytest -q

# 2. Run static type checking and linting
ruff check .
mypy src tests

# 3. Run interactive runtime firewall demo
python demo_runtime_firewall.py

# 4. Rebuild the Word (.docx) and PDF (.pdf) report documents
python scratch/report_builder/build_master.py
```
