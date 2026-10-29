# Self-Adapting Attribute-Based Access Control (SA-ABAC): A Proposed Framework for Combining Static Security Guardrails with Runtime Context Assessment in Autonomous AI Agents 

Karishma Thakur Vikas Kumar Shamshul Haque 

_Karishma Thakur: Bachelor of Technology, Computer Science & Engineering Project Guides: Vikas Kumar and Shamshul Haque Chhatrapati Shivaji Maharaj University Navi Mumbai, Maharashtra, India_ 

karishwork101@gmail.com 

### **_Abstract_** 

**Autonomous AI agents can call tools, read files, query databases, and trigger operations across software environments. Authorization for such agents should block unsafe actions without needlessly rejecting legitimate tasks. Static rules are predictable but may not anticipate every new task context, whereas semantic checks that rely on a second language model add inference cost and may themselves be targets of manipulation. This paper proposes Self-Adapting Attribute-Based Access Control (SA-ABAC), a conceptual framework that places a deterministic safety boundary in front of a runtime assessment of data sensitivity, goal alignment, and session reliability. The design has four layers: a static safety boundary, a trace and telemetry collector, a dynamic attribute inference engine, and an adaptive policy decision engine that can allow an action, transform it into a safer one, route it to human review, or block it. The paper specifies the proposed attributes, a bounded risk score with non-compensatory override rules, a threat model, and a plan for evaluating utility, security, and latency. SA-ABAC has not been implemented or evaluated. No experimental results are reported, and all formulas and thresholds are design proposals to be calibrated and tested in future work.** 

**_Keywords_ — AI agent security, attribute-based access control, runtime authorization, policy engine, prompt injection, least privilege.** 

## 1. Introduction 

attacker plants instructions in data that an application later retrieves, is one documented route to such outcomes [1]. 

Authorization should therefore consider more than whether a tool is available. It should also consider the requested operation, the resource involved, the user’s authority, the context of the request, and the possible consequences. Attribute-Based Access Control (ABAC) grants or denies requests using attributes of the subject and object, environment conditions, and a set of policies [2]. Recent work on agent governance, permission management, and protocollevel controls addresses related concerns [3–9]. 

This paper proposes SA-ABAC, a design that combines deterministic restrictions with a runtime assessment stage. It is a proposed architecture and evaluation plan. It has not been implemented, and no performance results are claimed. 

## _1.1. Problem Statement_ 

A purely static policy may reject a legitimate action because its sequence or parameters differ from what the policy anticipated. A permissive policy may instead allow an action that is unsafe in the current context. The design problem is to keep hard security boundaries while using context-sensitive evidence for actions that the static policy neither explicitly permits nor explicitly prohibits. 

Placing a second language model in front of every tool call is one way to assess context. It adds an inference step to each call and is itself a component that untrusted content may try to influence. A lighter assessment may be worth investigating, but whether it can be accurate enough is an open question that this paper does not answer. 

Autonomous AI agents differ from conventional chat interfaces because they act through tools and external services. A single task may involve reading a document, querying a database, modifying a record, or sending information elsewhere. If an agent misreads instructions or is influenced by malicious content, a useful workflow can produce unauthorized side effects. Indirect prompt injection, in which an 

## _1.2. Aim and Objectives_ 

The aim is to propose and specify a layered authorization framework for tool-using AI agents, together with a plan for evaluating it. The objectives are to: 

- define a layered architecture in which explicit high-risk prohibitions remain deterministic; 

1 

- assess data sensitivity, alignment with the user’s original goal, and session reliability at runtime; 

- define graduated outcomes (allow, transform, review, block) rather than only allow or deny; and 

- specify an evaluation plan that measures utility, security, and performance without assuming results in advance. 

## _1.3. Research Questions_ 

- **RQ1:** How can runtime context be incorporated into authorization while retaining a deterministic security boundary? 

- **RQ2:** Can goal-alignment and sensitivity signals help distinguish legitimate but unfamiliar actions from unsafe actions? 

- **RQ3:** What trade-offs arise between task utility, security, decision latency, and human-review frequency when the framework is tested? 

## 2. Background and Related Work 

## _2.1. Attribute-Based Access Control_ 

NIST describes ABAC as an access-control method in which requests to perform operations on objects are granted or denied based on attributes of the subject and object, environmental conditions, and a set of policies [2]. SA-ABAC keeps this policy-oriented foundation but proposes adding attributes computed at runtime from the agent’s task and behavior. These signals are intended to supplement explicit rules, not silently override them. 

## _2.2. Runtime Control of Agent Behavior_ 

AgentGuardian monitors execution traces during a controlled staging phase to learn legitimate behavior and input patterns, then derives policies that use runtime input context and control-flow dependencies to regulate tool calls [3]. A policy learned from staged traces may not cover tool sequences that were absent during staging. How often this would reject legitimate actions is an empirical question that the evaluation in Section 5 is designed to examine. 

SEAgent is a mandatory-access-control framework built on ABAC. It tracks agent-tool interactions in an informationflow graph and enforces configurable policies over entity attributes, with the aim of preventing privilege escalation [4]. 

MI9 proposes runtime governance for agentic AI, including agent-semantic telemetry, continuous authorization monitoring, goal-conditioned drift detection, and graduated containment [5]. LlamaFirewall is an open-source guardrail framework that includes an agent-alignment check intended to detect goal misalignment [9]. Goal-drift assessment and graded responses in SA-ABAC therefore overlap with ideas in [5, 9]; SA-ABAC is not claimed to be the first to use them. 

The proposed emphasis here is a deterministic floor that runtime signals cannot override, explicit non-compensatory override rules, and an inline tool-call mediator whose components can be ablated and measured separately. 

Table 1: Related approaches and their relation to SA-ABAC 

|**Work**|**Mechanism**|**Relation to SA-ABAC**|
|---|---|---|
|AgentGuardian|[3]<br>Policies learned from<br>staged traces using<br>input context and<br>control-flow<br>dependencies.|Staged-policy<br>comparison point.|
|SEAgent [4]|Mandatory access<br>control over an<br>information-flow graph<br>and entityattributes.|Attribute-policy<br>comparison point;<br>fuller flow tracking is<br>future work.|
|MI9 [5]|Telemetry, continuous<br>authorization,<br>goal-drift detection,<br>and graduated<br>containment.|Closest conceptual<br>overlap.|
|LlamaFirewall|[9]<br>Layered guardrails,<br>including an<br>agent-alignment check.|Model-based guardrail<br>comparison point.|
|Wu et al. [6]|Learned prediction of<br>user permission<br>decisions.|Informs human-review<br>design.|
|MCP-<br>Secure [7]|Runtime access control<br>for privilege-aware tool<br>use.|Informs tool-call<br>mediation.|
|MCP<br>guidance [8]|Scope minimization,<br>least privilege, and<br>protocol security<br>guidance.|Informs permission<br>scopes in Layer 0.|



## _2.3. Permission Management and Protocol-Level Controls_ 

Wu et al. study data-access permission management for AI agents. Their user study identified factors that shape people’s permission decisions, which they used to build a model that predicts those decisions [6]. This is relevant to the human-review outcome proposed here, because review requests should be limited and meaningful. 

MCP-Secure proposes a runtime access-control layer for privilege-aware tool use by LLM agents [7]. The Model Context Protocol security guidance describes risks such as the confused-deputy problem and token passthrough, and recommends scope minimization and least privilege [8]. These concerns inform the permission scopes in Layer 0. 

These works address related problems, but none validates the specific design proposed in this paper. Table 1 summarizes their relationship to SA-ABAC. 

## 3. Proposed SA-ABAC Architecture 

SA-ABAC is proposed as an inline governance component between an agent orchestrator and the tools or services the agent invokes. Each tool call passes through the four layers in Fig. 1 before execution. The framework is intended to fail safe: if a critical attribute or policy check cannot be evaluated, a sensitive action is not allowed merely because the evaluator failed. 

2 



<!-- Start of picture text -->
Agent orchestrator<br>Tool call and original task intent I 0<br>Layer 0: Static safety boundary fail<br>BLOCK<br>Deny list, permission scopes, hard rules<br>pass<br>Layer 1: Trace and telemetry<br>Task, tool, parameters, destination, history<br>Layer 2: Attribute inference (DAIE)<br>CSIk , GDSk , AV T Mk ∈ [0 ,  1]<br>Layer 3: Policy decision (APDE)<br>Risk score, thresholds, override rules<br>ALLOW TRANSFORM REVIEW BLOCK<br><!-- End of picture text -->

Figure 1: Proposed SA-ABAC architecture. Layer 0 blocks calls that violate hard policies. Calls that pass proceed through telemetry collection, attribute inference, and adaptive policy assessment to an ALLOW, TRANSFORM, REVIEW, or BLOCK outcome. 

## _3.4. Layer 2: Dynamic Attribute Inference Engine_ 

The Dynamic Attribute Inference Engine (DAIE) is proposed to estimate three signals, each normalized to [0 _,_ 1]. An implementation may use deterministic rules, classifiers, or embeddings, but each method must be documented and validated before operational use. The signals are design concepts, not validated metrics. 

## _3.4.1. Contextual Sensitivity Index (CSI)_ 

CSI estimates whether the payload or target resource is sensitive, such as credentials, personal information, confidential documents, or restricted business data. It combines _ρk_ , a pattern- and label-based score from regular expressions, resource labels, and data classifications, with _sk_ , the largest cosine similarity between the payload embedding and a set of embeddings _C_ sens representing sensitive categories (Eq. 1). The maximum is used so that CSI rises as the payload approaches any sensitive category. Semantic similarity is supporting evidence and should not be the sole basis for deciding that data may be shared. 



## _3.1. Threat Model and Assumptions_ 

The protected assets are the tools and data the agent can reach. The adversary can place instructions or misleading content in data the agent reads and can therefore influence the agent’s tool calls and their parameters [1]. We assume that (i) all tool calls are routed through SA-ABAC; (ii) the user’s original task statement, the Layer 0 configuration, and the SA-ABAC code and logs are trusted and protected from the agent; and (iii) the user is not malicious. Compromised hosts, malicious users, and side channels are out of scope. An adversary who knows the assessment method could craft actions that appear goal-consistent, so adaptive attacks of this kind are part of the planned evaluation in Section 5. 

## _3.2. Layer 0: Static Safety Boundary_ 

Layer 0 enforces non-negotiable restrictions. It denies a call that exceeds the user’s granted permission scopes, attempts a prohibited destructive operation, or violates an explicit data-handling rule. The deny list and scope model must be configured for the target environment, following leastprivilege practice [8]. Layer 0 does not rely on semantic similarity, and failure or unavailability of a later layer must never cause a Layer 0 denial to be bypassed. 

## _3.3. Layer 1: Trace and Telemetry Collector_ 

For each request, the collector records the initial task intent, the requested tool, its parameters (including any destination), the step number, and the prior tool-call history. It should minimize stored sensitive content, redact secrets where feasible, and apply access controls and retention limits to logs. The collector supplies context for later assessment and does not make the authorization decision. 

## _3.4.2. Goal Coherence and Drift Score (GDS)_ 

GDS estimates whether the proposed action _ak_ is consistent with the user’s original goal _I_ 0. The action is described by its tool, parameters, and destination, so that sending a report to the requesting user can be distinguished from sending it to an unrelated external address; embedding the tool name alone would not separate these cases (Eq. 2). Cosine similarity is one possible input. Similarity is not authorization, because an action can be related to a goal and still be unsafe. Comparing every step with _I_ 0 may also penalize legitimate investigations whose wording drifts from the original request, so whether to compare against the original request, a task plan, or a window of recent steps is a design choice to be tested. 



## _3.4.3. Agent Volatility and Trust Metric (AVTM)_ 

AVTM is a session-level signal based on observable execution events: repeated schema failures, timeouts, or unusual retries ( _Ek_ = 1), and validated successful calls ( _Uk_ = 1). It measures operational reliability, not trustworthiness. Equation 3 keeps it in [0 _,_ 1]. The gain _γ_ is chosen much smaller than the penalty _β_ , so that successful calls restore the score slowly, and the initial value _AV TM_ 0 = _v_ 0 is conservative. This limits an attacker’s ability to build a favorable score through benign calls. AVTM only influences the graded risk score and never overrides Layer 0 or the override rules in Section 4. The reset behavior (per session or per task) must be specified. A benign agent using an unreliable API may be penalized, and the evaluation should measure this effect. 



3 

## _3.5. Layer 3: Adaptive Policy Decision Engine_ 

The Adaptive Policy Decision Engine (APDE) applies policy to the Layer 0 result and available runtime signals. Four outcomes are proposed: 

- **ALLOW:** Proceed when the action is authorized and assessed as acceptable. 

- **TRANSFORM:** Replace a risky operation with a safer one, such as a read-only preview in place of a write, only when the transformation preserves the purpose of the task. Otherwise, REVIEW or BLOCK applies. 

- **REVIEW:** Pause and request human approval when risk or uncertainty exceeds a defined threshold. 

- **BLOCK:** Deny actions that violate hard rules or exceed the acceptable risk boundary. 

The engine should record the decision, the policy rule applied, the relevant signals, any uncertainty, and any transformation, so that each decision can be audited. Because the attributes are computed scores rather than assigned labels, auditability here means a logged rationale and not a formal guarantee. Only Layer 0 is deterministic. 

## 4. Proposed Decision Logic 

The expressions in this section are design choices, not validated formulas. They must be checked for meaningful ranges, correct directionality, and safe handling of missing values during implementation. 

## _4.1. Risk Score_ 

The context available for tool call _k_ is 



where _I_ 0 is the initial task intent, _Tk_ the requested tool, _Pk_ its parameters including destination, _k_ the step index, and _Hk−_ 1 the prior trace. One possible composite risk score is 



with _λi ≥_ 0 and _λ_ 1 + _λ_ 2 + _λ_ 3 = 1, so that _Rk_ lies in [0 _,_ 1]. The weights must be justified, and the inputs must be checked for compatible scales and correlation. In an early prototype, explicit rules and human review may be safer than an uncalibrated composite score. The composite should be adopted only if evaluation shows that it adds value over those rules. Layer 0 is evaluated first, and _Rk_ cannot override it. 

## _4.2. Decision Mapping and Override Rules_ 

For thresholds 0 _< τ_ 1 _< τ_ 2 _< τ_ 3 _≤_ 1, the graded decision is ALLOW if _Rk < τ_ 1; TRANSFORM if _τ_ 1 _≤ Rk < τ_ 2; REVIEW if _τ_ 2 _≤ Rk < τ_ 3; and BLOCK if _Rk ≥ τ_ 3. 

A weighted sum is compensatory: a low goal-drift score could offset a high sensitivity score. Some rules should not be tradable in this way, for example never sending sensitive data to an external destination without approval. SA-ABAC therefore adds non-compensatory override rules that can only make the outcome stricter. 

- **(O1)** If _CSIk ≥ τs_ and the destination is outside the trust boundary, the outcome is at least REVIEW. 

- **(O2)** If _Hk−_ 1 records access to a sensitive resource earlier in the session and the current call targets an external sink, the outcome is at least REVIEW. 

The final decision is the stricter of the graded decision and any override outcome. Rule O2 is a minimal use of session history. Fuller data-flow or taint tracking, as in informationflow-based approaches such as [4], is left for future work. 

## _4.3. Failure Handling and Calibration_ 

If an attribute cannot be computed, for example because an embedding service is unavailable, it is marked unknown instead of defaulting to a low value. For tools designated as sensitive, an unknown attribute leads to at least REVIEW. 

Weights, thresholds, and rule parameters must be chosen through documented design decisions. The parameters include _w_ 1, _w_ 2, _λ_ 1, _λ_ 2, _λ_ 3, _τ_ 1, _τ_ 2, _τ_ 3, _τs_ , _β_ , _γ_ , and _v_ 0. They must be calibrated on a development set separate from the test set and should not be presented as optimal before evaluation. 

## 5. Proposed Evaluation Methodology 

No experiments have been conducted for this version of the paper. This section is a plan for future work and does not describe completed work. 

## _5.1. Prototype and Baselines_ 

A prototype would place the policy engine between an agent orchestrator and a controlled set of mock or sandboxed tools. The agent model and version, sampling temperature, and number of repeated runs would be fixed and reported. Scenarios would be executed as live agent runs rather than replayed traces, because the effect of a blocked or transformed call on later steps, and therefore on task completion, can only be observed live. The planned configurations are: 

- (i) an unrestricted agent; 

- (ii) static enforcement only (Layer 0 and permission scopes); 

- (iii) a staged-trace policy in the style of [3], if it can be reproduced or approximated; 

- (iv) a language-model validator on every tool call, such as a guardrail in the style of [9]; 

- (v) a cascade that applies the static policy first and calls the language-model validator only for uncertain cases, which is the most direct alternative to SA-ABAC; and 

- (vi) the complete SA-ABAC configuration. 

The model, prompt, and hardware used for configurations (iv) and (v) would be reported. 

Ablation variants would add one signal at a time (CSI only, GDS only, AVTM only), separate the pattern-based and embedding-based parts of CSI, and test the override rules and TRANSFORM individually. Comparisons are meaningful only if every configuration runs the same scenarios under the same conditions. 

4 

## _5.2. Scenario Design_ 

- Routine benign tasks with expected tool sequences. 

- Novel but legitimate tasks whose tool sequences were not pre-recorded. 

- Sensitive-data tasks, including requests to export or transmit protected content. 

- Adversarial tasks involving indirect prompt injection, goal drift, permission escalation, or parameter manipulation, including attacks written by someone who knows the assessment method. 

- Failure and uncertainty cases, including missing attributes, tool errors, timeouts, and evaluator unavailability. 

The scenario set would be split into a development set, used to calibrate thresholds and weights, and a held-out test set that is used once. Scenarios would be labeled with a ground-truth policy before any run and, where possible, written by someone other than the person tuning the system. Established public agent-security benchmarks should be used alongside custom scenarios so that results can be compared with other work. The number of scenarios would be chosen after the test suite is designed, so that differences of practical interest can be detected. If a language model is used as a judge, its role, prompt, model version, and validation process should be disclosed, and a sample should receive human review. 

## _5.3. Metrics_ 

Table 2 gives the proposed metrics. Task completion rate (TCR) and false rejection rate (FRR) are not automatically complements. They sum to 100% only if they use the same set of legitimate tasks and every task is either completed or falsely rejected, with no other failure category. If execution errors or timeouts are possible, they should be reported independently. 

The metrics map to the research questions as follows. RQ1 is examined by comparing Layer 0 with the full configuration and by testing that Layer 0 denials hold when later layers fail. RQ2 is examined by comparing FRR on novel legitimate tasks and FAR on attacks across ablation variants. RQ3 is examined by reporting TCR, FRR, FAR, latency, and review rate together. 

## _5.4. Analysis and Reproducibility_ 

- Report confidence intervals (for example, Wilson intervals for proportions) and use paired comparisons on the same scenarios. 

- Repeat runs where the agent is nondeterministic and report variation, not only a single best run. 

- Separate policy-decision latency from total agent task duration. 

- Report security outcomes and utility costs together: false blocks, unsafe allows, review frequency, and transformed actions. 

Table 2: Proposed evaluation metrics 

|**Metric**|**Proposed definition and reporting note**|
|---|---|
|Task completion<br>rate (TCR)|Share of eligible tasks completed under<br>stated success criteria. Report the<br>denominator and completion criterion.|
|False rejection<br>rate (FRR)|Legitimate actions or tasks wrongly blocked<br>or sent to review, divided by all legitimate<br>ones. State the unit and whether REVIEW<br>or TRANSFORM counts as rejection.|
|False acceptance<br>rate (FAR)|Unsafe or unauthorized actions wrongly<br>allowed, divided by all such actions. Define<br>ground truth and report results by attack<br>type.|
|Decision latency|Time from receipt of a tool request to the<br>policy decision. Report p50 and p95 with<br>hardware, load, and cachingdetails.|
|Human-review<br>rate|Share of requests sent to a human. Indicates<br>dependence on manual review.|
|Transform rate<br>and fidelity|Frequency of TRANSFORM decisions and<br>whether the replacement action preserves<br>taskpurpose,judged byhuman review.|



- Preserve and, where permitted, publish scenario definitions, configurations, versioned code, and analysis scripts. 

- Claim an improvement only where a comparable baseline was tested under the same conditions. 

## 6. Expected Contributions 

If developed and evaluated, this work aims to contribute: 

- a layered design that preserves hard policy restrictions while adding runtime context assessment; 

- three bounded runtime attributes and explicit, noncompensatory rules for combining them; 

- a graduated response model that includes safe transformation and human review; and 

- an evaluation plan that reports security, utility, and latency together with appropriate statistical reporting. 

These are intended contributions of a proposal. They should not be read as demonstrated benefits until an implementation and evaluation support them. 

## 7. Limitations, Risks, and Future Work 

- Goal-alignment estimates can be wrong, and semantic similarity does not show that an action is authorized. 

- Sensitive-data detectors can miss new formats or flag benign content, so explicit data labels and conservative defaults remain important. 

- A composite score can hide errors when its inputs are poorly calibrated or correlated. 

- Embedding models and telemetry may themselves be manipulated, so the assessment layer is an attack surface that the threat model and evaluation must address. 

5 

- Runtime analysis adds overhead and new failure modes. 

- Only Layer 0 is deterministic. The adaptive layers offer no formal guarantee. 

Future work should implement a controlled prototype, validate each signal and decision rule, and test the framework against the baselines and adaptive attacks described above. Further extensions include data-flow tracking across a session and propagating attribute assertions across multi-agent delegation chains, for example through token claims. These extensions are not designed or evaluated here. 

## 8. Conclusion 

This paper proposes SA-ABAC, a layered authorization framework for tool-using AI agents. It combines a deterministic safety boundary with telemetry collection, runtime attribute assessment, and graduated policy decisions. The intent is to balance explicit security constraints with contextaware handling of legitimate but unfamiliar actions. The architecture, equations, and evaluation plan require further refinement and implementation. Because no experiments have been conducted, no quantitative results or claims of superiority are made. The next step is to build a controlled prototype and measure security, task utility, and latency against clearly defined baselines. 

## Acknowledgment 

**Use of generative AI.** Generative AI tools were used in preparing this paper. An earlier draft states on its title page that it was prepared using Gemini notebook source grounding, and the present version was edited, restructured, and checked for reference accuracy with the assistance of Claude (Anthropic). [Authors: confirm the tools used and what each contributed, and adjust this statement to your institution’s or target venue’s AI-disclosure policy.] The authors are responsible for the technical content and for verifying the cited sources. No AI-generated numerical results are presented as measurements. [Add other acknowledgments, such as supervisor or funding, here.] 

- [3] N. Abaev, D. Klimov, G. Levinov, D. Mimran, Y. Elovici, and A. Shabtai, “AgentGuardian: Learning access control policies to govern AI agent behavior,” 2026, arXiv:2601.10440. [Online]. Available: https://arxiv.org/abs/2601.10440. 

- [4] Z. Ji, D. Wu, W. Jiang, P. Ma, Z. Li, Y. Gao, S. Wang, and Y. Li, “Taming various privilege escalation in LLM-based agent systems: A mandatory access control framework,” 2026, arXiv:2601.11893. [Online]. Available: https://arxiv.org/abs/2601.11893. 

- [5] C. L. Wang, T. Singhal, A. Kelkar, and J. Tuo, “MI9: An integrated runtime governance framework for agentic AI,” 2025, arXiv:2508.03858. [Online]. Available: ht tps://arxiv.org/abs/2508.03858. 

- [6] Y. Wu, K. Yang, F. Roesner, T. Kohno, N. Zhang, and U. Iqbal, “Towards automating data access permissions in AI agents,” 2025, arXiv:2511.17959. [Online]. Available: https://arxiv.org/abs/2511.17959. 

- [7] G. Singh and V. K. Madisetti, “MCP-Secure: A runtime access controllayer for privilege-aware LLMagent tooling,” _IEEE Open Journal of the Computer Society_ , vol. 7, pp. 504–513, 2026, doi: 10.1109/OJCS.2 026.3664314. 

- [8] Model Context Protocol, “Security best practices,” MCP Specification, version 2025-11-25. [Online]. Available: https://modelcontextprotoc ol.io/specification/2025-11-25/basi c/security_best_practices (accessed Oct. 22, 2026). 

- [9] S. Chennabasappa et al., “LlamaFirewall: An open source guardrail system for building secure AI agents,” 2025, arXiv:2505.03574. [Online]. Available: http s://arxiv.org/abs/2505.03574. 

## References 

- [1] K. Greshake, S. Abdelnabi, S. Mishra, C. Endres, T. Holz, and M. Fritz, “Not what you’ve signed up for: Compromising real-world LLM-integrated applications with indirect prompt injection,” 2023, arXiv:2302.12173. [Online]. Available: https:// arxiv.org/abs/2302.12173. 

- [2] V. C. Hu, D. Ferraiolo, R. Kuhn, A. Schnitzer, K. Sandlin, R. Miller, and K. Scarfone, “Guide to attribute based access control (ABAC) definition and considerations,” NIST Special Publication 800-162, Jan. 2014, updated Aug. 2, 2019, doi: 10.6028/NIST.SP.80 0-162. [Online]. Available: https://csrc.nis t.gov/pubs/sp/800/162/upd2/final. 

6 

