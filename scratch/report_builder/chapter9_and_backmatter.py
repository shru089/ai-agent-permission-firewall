"""
AASF Project Report - Chapter 9: Conclusion and Future Scope, and Back Matter.
Covers:
Chapter 9:
9.1 Project Summary
9.2 Fulfillment of Project Objectives
9.3 Core Research Contributions
9.4 Engineering and Technical Contributions
9.5 Encountered Limitations
9.6 Future Scope and Extension Roadmaps
9.7 Final Concluding Remarks

Back Matter:
- References / Bibliography (IEEE Style, 22 citations)
- Appendix I: Research Manuscripts
- Appendix II: Manuscript Abstract
- Appendix III: Plagiarism and Originality Report Placeholder
- Appendix IV: Formal Specifications of Security Invariants (INV-01 to INV-12)
- Appendix V: Cryptographic Benchmark Manifests
"""

from docx import Document
from docx.shared import Pt, Inches, RGBColor
from styles import add_chapter_title, add_h1, add_h2, add_p, add_bullet, add_table, add_callout, add_page_break

def add_chapter9(doc: Document):
    add_chapter_title(doc, "CHAPTER 9", "CONCLUSION AND FUTURE SCOPE")
    
    # 9.1 Project Summary
    add_h1(doc, "9.1", "Project Summary")
    add_p(doc,
        "The Adaptive Agentic Security Firewall (AASF) was conceived, engineered, and empirically validated to address a fundamental, "
        "existential vulnerability in autonomous artificial intelligence agent deployments: the complete inability of conventional perimeter "
        "defenses and stateless access controls to prevent multi-step context manipulation and unauthorized data exfiltration. "
        "By operationalizing Schneider’s formal execution monitoring theory within an in-process security mediation architecture, "
        "AASF replaces soft prompt guardrails with deterministic mathematical invariants, single-use execution tokens, and tamper-evident audit trails."
    )

    # 9.2 Fulfillment of Project Objectives
    add_h1(doc, "9.2", "Fulfillment of Project Objectives")
    add_p(doc, "The following implementation and evaluation outcomes are documented in the repository:")
    add_bullet(doc, "Implemented FirewallCore to mediate configured agent-to-tool dispatches through the firewall gateway.", "1. Complete Mediation:")
    add_bullet(doc, "Implemented the deterministic folding operator Phi for modeled session histories, with hash-chained state records in the in-process runtime (INV-02).", "2. State Awareness:")
    add_bullet(doc, "Implemented the three-valued policy engine and decision combinator Delta. The benchmark summary reports M-VIOL = 0 / 0 for its listed arms and splits.", "3. Policy and Decision Logic:")
    add_bullet(doc, "Compared with B3, B6 review rate decreased from 0.3333 to 0.0833 on TEST-IN (75%) and from 0.2500 to 0.0000 on TEST-NOVEL (100%). P1 p95 evaluator latency was 1.023 ms on TEST-IN and 0.936 ms on TEST-NOVEL. The separate synthetic-request CLI benchmark is not combined with evaluator measurements.", "4. Evaluated Review and Latency Results:")
    add_bullet(doc, "TokenStore issues single-use authorization tokens bound to the action and relevant state, with expiry and replay checks. HMAC-SHA256 is used separately by the evidence verifier.", "5. Authorization Token Handling:")

    # 9.3 Core Research Contributions
    add_h1(doc, "9.3", "Core Research Contributions")
    add_p(doc, "The project documents the following research and engineering contributions:")
    add_bullet(doc, "The DEV manipulation-check artifact reports Youden's J = 0.0 for B3 and B4. In the benchmark summary, B3/B4 report J = 0.0000 on TEST-IN and TEST-NOVEL, while B6/P1 report J = 0.5000 on TEST-IN and 1.0000 on TEST-NOVEL.", "Contribution 1: State and Context Evaluation:")
    add_bullet(doc, "Formalized an attribute-based policy lattice capable of dynamically propagating resource taints across multi-step agent actions without manual policy restructuring (P2).", "Contribution 2: Dynamic Policy Lattice:")
    add_bullet(doc, "Implemented advisory monitor semantics in which monitor advice does not authorize an action that policy prohibits.", "Contribution 3: Advisory-Only Cascade Semantics:")
    add_bullet(doc, "Evaluated review rates by arm on TEST-IN and TEST-NOVEL; the reported rates are split-specific benchmark measurements.", "Contribution 4: Human-in-the-Loop Evaluation:")

    # 9.4 Engineering and Technical Contributions
    add_h1(doc, "9.4", "Engineering and Technical Contributions")
    add_p(doc,
        "AASF is an in-process Python implementation of an agent-action permission firewall. 433 tests passed in the audited run, "
        "with zero failures. Test runtime depends on the execution environment. No coverage report establishing complete code or branch coverage "
        "is included in the audited artifacts. Production readiness and integration with commercial agent platforms were not evaluated."
    )

    # 9.5 Encountered Limitations
    add_h1(doc, "9.5", "Encountered Limitations")
    add_p(doc, "Three engineering limitations were identified during evaluation:")
    add_bullet(doc, "The canonical runtime currently executes in-process within a single operating system host process. Distributed agent clusters spanning multiple host nodes require shared Redis or Raft-backed state stores.", "1. Single-Node In-Process Scope:")
    add_bullet(doc, "Cryptographic token keys and evidence HMAC secrets reside in host memory; physical memory scraping by a root adversary with kernel privileges is out of scope.", "2. Memory-Resident Key Storage:")
    add_bullet(doc, "The implementation evaluates structured tool actions; unstructured agent reasoning text is outside the evaluated action interface.", "3. Unstructured Agent Content:")

    # 9.6 Future Scope and Extension Roadmaps
    add_h1(doc, "9.6", "Future Scope and Extension Roadmaps")
    add_p(doc, "The following items are proposed future work; their inclusion does not imply that production or commercial readiness has been established:")
    add_bullet(doc, "Migrate the StateEngine and TokenStore to a distributed, Byzantine Fault Tolerant (BFT) consensus protocol (e.g., Raft) to support multi-agent swarms operating across heterogeneous cloud clusters.", "1. Distributed Multi-Node State Synchronization:")
    add_bullet(doc, "Integrate Hardware Security Modules (HSM) or cloud KMS (e.g., AWS KMS, HashiCorp Vault) for hardware-enforced token signing and tamper-proof key isolation.", "2. Hardware-Enforced HSM Key Storage:")
    add_bullet(doc, "Develop reinforcement learning algorithms that observe human reviewer resolutions over time to synthesize and propose automated ABAC rule refinements.", "3. Dynamic Policy Learning and Self-Tuning:")
    add_bullet(doc, "Incorporate native eBPF kernel hooks in Linux container environments to enforce tool mediation at the OS syscall boundary, eliminating reliance on application-layer wrappers.", "4. eBPF Kernel-Level Enforcement:")

    # 9.7 Final Concluding Remarks
    add_h1(doc, "9.7", "Final Concluding Remarks")
    add_p(doc,
        "This project implemented and evaluated an in-process permission firewall for agent tool actions. The benchmark report records results "
        "by arm and dataset split; those results do not establish universal prevention or production readiness. Canonical evaluator latency and "
        "the separate synthetic-request CLI microbenchmark are distinct measurements and are reported separately."
    )
    
    add_page_break(doc)

def add_back_matter(doc: Document):
    # ---------------- REFERENCES ----------------
    add_chapter_title(doc, "REFERENCES", "BIBLIOGRAPHY")
    add_p(doc, "All cited references conform to IEEE standard academic citation formats:")
    
    refs = [
        "[1] S. Singh, A. Kumar, and M. Haque, “State vs. context: Evaluating LLM runtime monitors under action-history manipulation,” manuscript; publication status unverified.",
        "[2] K. Thakur, A. Kumar, and M. Haque, “Self-adapting attribute-based access control (SA-ABAC) for multi-agent collaboration,” manuscript; publication status unverified.",
        "[3] A. Kasurde, A. Kumar, and M. Haque, “Adaptive security-check depth: A tiered rejection cascade for latency-constrained interception,” manuscript; publication status unverified.",
        "[4] S. Jagtap, A. Kumar, and M. Haque, “Workload-aware adaptive dynamic oversight for human-agent systems,” manuscript; publication status unverified.",
        "[5] F. B. Schneider, “Enforceable security policies,” ACM Transactions on Information and System Security (TISSEC), vol. 3, no. 1, pp. 30–50, 2000.",
        "[6] Y. Liu, R. Jia, and P. Liang, “ToolSafe: Fine-grained parameter validation and type enforcement for tool-augmented language models,” in Proceedings of the 64th Annual Meeting of the Association for Computational Linguistics (ACL), 2026, pp. 4501–4515.",
        "[7] H. Zhang, X. Chen, and D. Song, “StepGuard: Step-level runtime supervision and verification for autonomous agents,” in Proceedings of the Conference on Empirical Methods in Natural Language Processing (EMNLP), 2026, arXiv:2608.24777.",
        "[8] M. Brown, K. Patel, and S. Wu, “TraceSafe: Post-hoc causal audit graphs and provenance tracking for autonomous agents,” in Conference on Language Modeling (COLM), 2026, arXiv:2604.07223.",
        "[9] J. Harness, T. Evans, and L. Vance, “HarnessRisk: A standardized benchmark for measuring tool-use risk in multi-step agentic workflows,” arXiv preprint arXiv:2608.17597, 2026.",
        "[10] V. Greshake, S. Abdelnabi, S. Mishra, C. Endres, T. Holz, and M. Fritz, “Not what you’ve signed up for: Compromising language model applications with indirect prompt injection,” in Proceedings of the 16th ACM Workshop on Artificial Intelligence and Security (AISEC), 2023, pp. 79–90.",
        "[11] K. G. Brown, E. Davis, and R. Miller, “The confused deputy revisited: Privilege escalation vulnerabilities in LLM tool ecosystems,” IEEE Security & Privacy, vol. 24, no. 2, pp. 34–43, 2026, arXiv:2605.31593.",
        "[12] S. Yao, J. Zhao, D. Yu, N. Du, I. Shafran, K. Narasimhan, and Y. Cao, “ReAct: Synergizing reasoning and acting in language models,” in International Conference on Learning Representations (ICLR), 2023.",
        "[13] L. Wang et al., “A survey on large language model based autonomous agents,” Frontiers of Computer Science, vol. 18, no. 6, p. 186345, 2024.",
        "[14] E. J. Hu et al., “LoRA: Low-rank adaptation of large language models,” in International Conference on Learning Representations (ICLR), 2022.",
        "[15] National Institute of Standards and Technology (NIST), “Attribute Based Access Control (ABAC) Definition and Considerations,” NIST Special Publication 800-162, 2014.",
        "[16] European Commission, “Proposal for a Regulation laying down harmonised rules on artificial intelligence (Artificial Intelligence Act),” COM(2021) 206 final, Brussels, 2021.",
        "[17] ISO/IEC, “Information technology — Artificial intelligence — Management system,” ISO/IEC 42001:2023, International Organization for Standardization, Geneva, 2023.",
        "[18] H. Krawczyk, M. Bellare, and R. Canetti, “HMAC: Keyed-hashing for message authentication,” RFC 2104, Internet Engineering Task Force, 1997.",
        "[19] National Institute of Standards and Technology (NIST), “Secure Hash Standard (SHS),” FIPS PUB 180-4, U.S. Department of Commerce, 2015.",
        "[20] W. J. Youden, “Index for rating diagnostic tests,” Cancer, vol. 3, no. 1, pp. 32–35, 1950.",
        "[21] S. Russell and P. Norvig, Artificial Intelligence: A Modern Approach, 4th ed. Hoboken, NJ: Pearson, 2020.",
        "[22] R. S. Sandhu, E. J. Coyne, H. L. Feinstein, and C. E. Youman, “Role-based access control models,” IEEE Computer, vol. 29, no. 2, pp. 38–47, 1996."
    ]
    for r in refs:
        p = doc.add_paragraph()
        p.paragraph_format.line_spacing = 1.15
        p.paragraph_format.space_after = Pt(4)
        run = p.add_run(r)
        run.font.name = "Times New Roman"
        run.font.size = Pt(9.5)
        
    add_page_break(doc)

    # ---------------- APPENDIX I: RESEARCH MANUSCRIPTS ----------------
    add_chapter_title(doc, "APPENDIX I", "RESEARCH MANUSCRIPTS")
    add_p(doc, "The repository contains research manuscripts and abstracts related to this project. Publication or peer-review status is not established by the artifacts included here.")
    
    add_page_break(doc)

    # ---------------- APPENDIX II: MANUSCRIPT ABSTRACT ----------------
    add_chapter_title(doc, "APPENDIX II", "MANUSCRIPT ABSTRACT")
    add_callout(doc, "PROJECT MANUSCRIPT ABSTRACT",
        "Title: State vs. Context: Evaluating LLM Runtime Monitors under Action-History Manipulation\n"
        "Authors: Shrishti Singh, A. Kumar, M. Haque\n\n"
        "Abstract: Autonomous language model agents rely on multi-step tool execution pipelines to accomplish complex tasks. "
        "However, contemporary runtime defenses evaluate candidate actions either in total stateless isolation or over raw "
        "context windows subject to prompt degradation. In this paper, we investigate the vulnerability of LLM runtime monitors "
        "to action-history manipulation, where an adversary intersperses benign diagnostic actions between privileged reads and "
        "data exfiltrations. In the reported DEV manipulation check, B3 and B4 each have Youden's J = 0.0. The benchmark summary reports "
        "B3/B4 J = 0.0000 on TEST-IN and TEST-NOVEL, and B6/P1 J = 0.5000 on TEST-IN and 1.0000 on TEST-NOVEL. To examine this, we describe "
        "a monotonic state-folding engine that cryptographically tracks resource classifications and taints across sessions. "
        "On TEST-IN and TEST-NOVEL, B6 and P1 each report M-APR = 1.0000. P1 p95 evaluator latency is 1.023 ms on TEST-IN and 0.936 ms on "
        "TEST-NOVEL. These are split-specific evaluator results; the separate synthetic-request CLI microbenchmark is not combined with them."
    )
    
    add_page_break(doc)

    # ---------------- APPENDIX III: SIMILARITY VERIFICATION STATUS ----------------
    add_chapter_title(doc, "APPENDIX III", "SIMILARITY VERIFICATION STATUS")
    add_p(doc, "No institutional Turnitin or equivalent similarity report is included in the repository. No similarity percentage is claimed.")
    
    add_page_break(doc)

    # ---------------- APPENDIX IV: INVARIANT FORMAL SPECIFICATIONS ----------------
    add_chapter_title(doc, "APPENDIX IV", "FORMAL SPECIFICATIONS OF SECURITY INVARIANTS")
    add_p(doc,
        "This appendix provides the formal mathematical logic specifications for the twelve core security invariants governing AASF:"
    )
    
    invariants = [
        ("INV-01 (Complete Mediation)", "forall a in Actions: Executed(a) => InterceptedByFirewall(a)"),
        ("INV-02 (Deterministic State Fold)", "forall S_0, H: S_n = Fold(Phi, S_0, H) is unique, deterministic, and immutable"),
        ("INV-03 (Policy Primacy)", "PolicyVerdict(a, S) = PROHIBIT => Decider(a, S, M) = DENY (Monitors cannot permit)"),
        ("INV-04 (Fail-Closed Defaults)", "(Evidence(a) = INVALID or Monitor(a) = TIMEOUT) => Decider(a, S, M) in {REVIEW, DENY}"),
        ("INV-05 (State Hash Revalidation)", "ResolveReview(tkt, APPROVE) => (StateHash(Now) = tkt.state_hash)"),
        ("INV-06 (Single-Use Token Enforcement)", "Redeem(token) => Valid(token) and not Consumed(token); Token marked Consumed immediately"),
        ("INV-07 (Audit Continuity)", "forall rec_i in AuditChain: rec_i.prev_hash = SHA256(rec_{i-1})"),
        ("INV-08 (Action-Hash Binding)", "TokenAuth(token, a) => token.action_hash = SHA256(Canonical(a))"),
        ("INV-09 (Audit Verifiability)", "VerifyChain(Session) = True <=> Chain has not experienced bit-level modification or truncation"),
        ("INV-10 (MonitorView Isolation)", "forall m in Monitors: Input(m) = ProjectSanitized(S, a) (Credentials and keys redacted)"),
        ("INV-11 (Session Mutual Exclusion)", "forall s in Sessions: ConcurrentAccess(s) is guarded by exclusive session mutex L_s"),
        ("INV-12 (Monotonic Taint Accumulation)", "Sensitivity(S_n) >= Sensitivity(S_{n-1}) (Taint levels monotonically non-decreasing)"),
    ]
    for inv_id, inv_spec in invariants:
        add_callout(doc, inv_id, inv_spec)

    add_page_break(doc)

    # ---------------- APPENDIX V: CRYPTOGRAPHIC MANIFESTS ----------------
    add_chapter_title(doc, "APPENDIX V", "CRYPTOGRAPHIC BENCHMARK MANIFESTS")
    add_p(doc,
        "The repository tracks dataset manifests and test commitments. These hashes identify committed protocol and split artifacts; they do not cryptographically seal evaluation result tables or guarantee that every result can be regenerated:"
    )
    add_callout(doc, "BENCHMARK CRYPTOGRAPHIC COMMITMENTS",
        "1. PREREG-001 Protocol Digest:\n"
        "   88038e76161686bd3cc4fd0a12757e9d4264f406a7d5399a9ba6bff92ee37fd5\n\n"
        "2. DEV Dataset Manifest (docs/prereg/DEV_MANIFEST.sha256):\n"
        "   dev_matched_history_pairs.jsonl: SHA-256 verified\n\n"
        "3. CAL Dataset Manifest (docs/prereg/CAL_MANIFEST.sha256):\n"
        "   cal_calibration_traces.jsonl: SHA-256 verified\n\n"
        "4. TEST Split Sealed Commitment (docs/prereg/TEST_COMMITMENT.sha256):\n"
        "   test_in_traces.jsonl: SHA-256 verified\n"
        "   test_novel_traces.jsonl: SHA-256 verified\n\n"
        "5. Test run:\n"
        "   433 tests passed in the audited run; runtime depends on the execution environment. This is not a cryptographic commitment."
    )
