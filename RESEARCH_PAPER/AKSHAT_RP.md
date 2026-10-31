# Adaptive Security-Check Depth: A Tiered Rejection Cascade for Mitigating Indirect Prompt Injection in LLM Agents 

Akshat Kasurde Vikas Kumar Shamshul Haque 

Akshat Kasurde: Bachelor of Technology, Computer Science & Engineering 

Project Guides: Vikas Kumar and Shamshul Haque 

Chhatrapati Shivaji Maharaj University 

Navi Mumbai, Maharashtra, India 

akshatkasurde@gmail.com 

**_Abstract_ —Tool-using large language model agents require safeguards against actions influenced by malicious instructions in external content. Auditing every proposed action with a larger model introduces additional processing, while a single lightweight guard may leave attacks undetected. This paper examines Adaptive Security-Check Depth (ASCP), a tiered architecture combining deterministic screening, a lightweight language-model auditor, and a deeper auditor. Under the rejection policy described here, an early failure blocks a request, while requests not rejected by earlier stages receive a final deep audit. The supplied evaluation summary contains 580 requests: 330 attacks and 250 benign requests. FullCascade blocks 290 attacks, compared with 247 for DeepOnly, corresponding to filter-bypass rates of 12.12% and 25.15%, respectively. Neither strategy blocks a benign request in this evaluation. FullCascade uses 386 deep-auditor invocations rather than 580, but its reported mean latency is higher: 509.94 ms rather than 358.24 ms. These findings indicate a tradeoff between observed filtering effectiveness, deep-model invocation count, and sequential latency, rather than a universal speed improvement. The paper distinguishes filter bypass from downstream compromise, separates rejection routing from early acceptance, and identifies the implementation and provenance information required for reproducibility.** 

**_Index Terms_ —LLM agents, indirect prompt injection, security guardrails, rejection cascade, adaptive auditing, tool-call filtering.** 

## I. INTRODUCTION 

Tool-using large language model agents can translate user requests into actions such as reading documents, querying databases, modifying files, and sending information to external services. These capabilities create security requirements that extend beyond the generation of text. Agentic security involves the interaction of planning, memory, tool use, and autonomy, as discussed by Chhabra et al. [2]. 

A proposed tool action may be syntactically valid while remaining inconsistent with the user’s intended task. Runtime enforcement approaches therefore examine agent behavior against explicit constraints before actions proceed [1], [5]. Such enforcement is particularly important when the agent has processed material that is not controlled by the legitimate user. 

Indirect prompt injection concerns this separation between instructions and externally obtained data. An attacker may 

influence a retrieved document, message, or page without directly controlling the user’s request. The security problem arises when lower-trust material influences the agent’s behavior in ways that cross the intended authorization boundary. This issue forms part of the wider agentic threat landscape reviewed in [2]. 

This paper studies the allocation of auditing effort across a sequence of checks. A deterministic stage can reject requests matching configured patterns. A lightweight language model can evaluate requests that survive those checks. A deeper auditor can then examine the remaining requests. The resulting architecture is called Adaptive Security-Check Depth (ASCP). 

The motivation is not that every later stage must be more accurate on every sample. Different checks may reject different subsets of attacks. The central question is whether their sequential combination offers a useful operating point when attack rejection, benign blocking, model invocation count, and latency are evaluated together. 

These objectives must be distinguished. Avoiding a deepmodel call does not automatically reduce total response time because preliminary checks also consume time. Work on agentsystem latency motivates measuring the full pipeline rather than relying on model size or invocation count alone [3]. Similarly, a zero observed false positive count does not establish that every legitimate request will be accepted. 

The contributions of this paper are: 

- 1) A specification of three-stage rejection routing and its distinction from early-acceptance routing. 

- 2) An organized analysis of the supplied security counts, including explicit false-negative counts and metric denominators. 

- 3) A comparison of deep-auditor invocation savings with measured sequential latency. 

- 4) An account of the provenance, failure-handling, and reproducibility requirements needed to substantiate the reported evaluation. 

To ensure scientific reproducibility, the implementation source code, evaluation dataset, and raw results logs are made 

publicly available at https://github.com/akshat33-spec/ai-agent -firewall. 

The numerical results are taken from the supplied 580request evaluation summary. They have not been independently regenerated from the complete benchmark artifacts in preparing this manuscript. Claims that require those artifacts are therefore identified separately from the reported aggregate observations. 

## II. RELATED WORK 

## _A. Runtime Enforcement_ 

AgentSpec introduces a domain-specific language for specifying and enforcing runtime constraints on LLM agents [1]. Its rules combine triggering events, predicates, and enforcement actions. This structure permits interventions such as termination, user inspection, or additional checking when a proposed action violates an application requirement. 

ASCP shares the objective of examining actions before execution, but addresses a narrower architectural question. Rather than introducing a general policy language, it studies the ordering of deterministic and model-based checks. The current evaluation does not compare ASCP experimentally against AgentSpec, and no superiority over that framework is claimed. 

## _B. Security Across Agentic Workflows_ 

Chhabra et al. survey threats, defenses, evaluation approaches, and open challenges in agentic AI security [2]. This broader perspective places tool-call filtering within a system that also includes planning, memory, communication, and interaction with external resources. 

A guard at one execution boundary is therefore not equivalent to complete protection of an agentic workflow. ASCP evaluates whether labeled requests are allowed or blocked. It does not establish that all other channels through which an attacker may influence the agent are protected. 

## _C. Latency and Model Orchestration_ 

Park et al. survey response latency in LLM-based agent systems [3]. Their treatment motivates separating the sources of delay within an agent pipeline and evaluating responsiveness at the system level. 

This distinction is directly relevant to cascaded security checks. Early rejection may avoid a deep invocation for some requests, while preliminary audits add work to requests that continue. ASCP therefore reports both deep-call counts and end-to-end latency, rather than treating either quantity as a substitute for the other. 

## _D. Lineage-Aware Memory Governance_ 

Sangaraju and Vissa study lineage-aware memory governance through a derivation-gated framework for privacy-preserving, column-level access control in enterprise AI agents [4]. This work addresses authorization involving retained and derived information. 

The connection to ASCP is the distinction between possessing information and having authority to use or disclose 

it. However, lineage-based access control is not equivalent to prompt-injection classification. The supplied ASCP evaluation does not demonstrate implementation of derivation-gated memory governance or column-level information-flow policies. 

## _E. Least-Privilege Tool Mediation_ 

MCP-Secure is a host-side runtime access-control layer for Model Context Protocol tooling [5]. It applies scoped access, read-only defaults, and approval-gated privilege elevation, using a session-level state machine. 

These controls operate at a different layer from a textual maliciousness classifier. A request can appear benign while exceeding its permitted privileges. Conversely, an otherwise permitted tool can be invoked with unsafe arguments. Semantic screening and privilege enforcement therefore address distinct concerns. 

ASCP should not be described as implementing MCPSecure or providing MCP integration unless the corresponding implementation is supplied. The present comparison concerns design objectives, not an evaluated integration. 

## _F. Positioning and Research Questions_ 

The cited work motivates explicit runtime constraints, broader agentic threat analysis, end-to-end latency measurement, memory authorization, and least-privilege tool mediation [1]–[5]. 

Within this context, ASCP examines four questions: 

- 1) Does the cascade block more labeled attacks than either model operating alone? 

- 2) Does it introduce additional observed blocks among benign requests? 

- 3) How many deep-auditor calls are avoided? 

- 4) Do avoided calls produce lower measured end-to-end latency? 

These questions define a limited empirical contribution. They do not assert that staged defenses are new in general or that the evaluated cascade is universally preferable. 

## III. THREAT MODEL AND SCOPE 

## _A. System Model_ 

Let _u_ denote a legitimate user task, _c_ denote externally obtained content, and _a_ = ( _f, x_ ) denote a proposed tool action with function name _f_ and arguments _x_ . A guard evaluates an available representation _z_ and returns: 



The representation _z_ is implementation-dependent. It may contain only ( _f, x_ ), or it may additionally contain _u_ and selected context from _c_ . This difference determines which authorization relationships the guard can inspect. 

The intended enforcement location is immediately before tool execution. Runtime interception is consistent with the broader enforcement approach illustrated by AgentSpec and MCP-Secure [1], [5], but integration with those systems is not part of the supplied evaluation. 



<!-- Start of picture text -->
External content c<br>Trusted user task<br>u attacker-controlledPotentially<br>Tool-using LLM agent<br>Proposed tool action<br>a = ( f, x )<br>Execution boundary<br>ASCP guard<br>Evaluates implemented input z<br>BLOCK ALLOW<br>No tool execution Tool execution<br><!-- End of picture text -->

Fig. 1. Intended placement of ASCP before tool execution. Dashed input borders indicate potentially attacker-controlled content. The figure does not assume that the guard receives all information available to the agent. 

Figure 1 illustrates this intended placement. The user task and external content are shown as inputs to the agent. Their availability to the guard depends on the implemented input representation. 

## _B. Attacker Capabilities_ 

## _D. Evaluation Endpoint_ 

An attack bypasses the evaluated filter when its labeled request receives ALLOW. A benign request contributes a false positive when it receives BLOCK. 

This endpoint does not establish that the agent would generate the proposal naturally, that the tool would accept it, or that the action would cause a successful compromise. Those outcomes require end-to-end experiments. 

## IV. THE ASCP FRAMEWORK 

## _A. Tier 1: Deterministic Screening_ 

The first stage applies fixed checks to the proposed request. The supplied manuscript describes patterns involving commands or strings such as rm -rf, drop table, sudo, and curl http. 

These examples identify the stated rule family, not a complete specification of the matcher. Case sensitivity, argument parsing, escaping, and treatment of quoted content require the actual implementation. 

A literal match does not independently establish malicious intent. A legitimate security task may quote a dangerous command without requesting its execution. Evaluation of T1 should therefore include such benign cases. 

T1 rejects a request when its configured conditions hold. Otherwise, the request remains eligible for model-based auditing. 

## _B. Tier 2: Lightweight Auditing_ 

The lightweight auditor produces: 

For indirect injection, the attacker controls some external content the agent may encounter, rather than the legitimate user’s task. The objective is to influence the agent toward an unauthorized proposed action. 

If malicious content is also included in the guard’s input, the guard itself receives an adversarial text channel. Prompt delimiters and role descriptions should therefore be documented as implementation choices, not treated as proof that the auditor cannot be manipulated. 

The supplied dataset description includes both direct and indirect injections. Without category-specific results, the aggregate numbers cannot be interpreted as an indirect-injection-only performance estimate. 

## _C. Trust Boundaries_ 

Three boundaries are relevant: 

- Trusted user instructions versus externally obtained content. 

- A proposed tool action versus authorization to execute it. 

- A guard’s textual response versus the programmatic verdict extracted from that response. 

The third boundary matters when a model returns explanations, multiple verdict words, or malformed output. A parser can change the effective decision even if the raw model response is retained. 



An explicit uncertainty state separates an unresolved assessment from an affirmative pass. Its operational consequence depends on the routing policy. 

In rejection routing, FAIL blocks the request, while both PASS and UNSURE continue to T3. A lightweight pass therefore means that T2 did not reject; it does not constitute final authorization. 

## _C. Tier 3: Deep Auditing_ 

The deep auditor evaluates requests that survive earlier checks. Under the rejection policy, it supplies the final authorization decision. 

The architecture does not assume that a larger model is correct on every request accepted by a smaller model. Different guards may have overlapping or complementary error sets. The observed overlap must be measured rather than inferred from model size. 

## _D. Rejection Routing_ 

Figure 2 summarizes the rejection policy. Table I provides the corresponding verdict-to-action mapping. An error policy must additionally define behavior for malformed output and runtime failures. 

For valid verdicts, the sequential procedure is: 

1) Evaluate T1. Return BLOCK if it fails. 



<!-- Start of picture text -->
Proposed tool request<br>FAIL<br>T1: Deterministic screening BLOCK<br>PASS<br>FAIL<br>T2: Lightweight auditor BLOCK<br>PASS or<br>UNSURE<br>FAIL<br>T3: Deep auditor BLOCK<br>PASS<br>ALLOW<br><!-- End of picture text -->

Fig. 2. ASCP rejection-cascade routing for valid verdicts. An early failure blocks the request. A lightweight PASS or UNSURE continues to the deep auditor. Error handling is specified separately. 

associated with the 580-request results must establish which policy was executed. 

The reported LightweightDeep total of 402 deep calls is numerically consistent with rejecting 178 requests before T3 out of 580. This is an aggregate consistency check, not independent verification of the routing code. 

## _F. Prompt Inputs and Parsing_ 

The mini-pilot prompts show a tool name and arguments. They do not establish that the guards received the trusted task, retrieved content, or explicit [UNTRUSTED] markers. Those inputs should be claimed only for an implementation whose serialized prompts demonstrate them. 

The mini-pilot also reports a parser that selects the last occurrence of PASS, FAIL, or UNSURE, defaulting to UNSURE when no token appears. This differs from requiring an exacttoken response. 

Its use in the primary evaluation remains a provenance question. Raw responses, parsed verdicts, and final actions should be retained separately so that parsing effects can be distinguished from model classifications. 

TABLE I 

REJECTION-CASCADE ROUTING POLICY 

## V. EXPERIMENTAL METHODOLOGY 

## _A. Evaluation Set_ 

|Stage|Verdict|Action|
|---|---|---|
|T1|FAIL|Block; skip T2 and T3|
|T1|PASS|Invoke T2|
|T2|FAIL|Block; skip T3|
|T2|PASS|Invoke T3|
|T2|UNSURE|Invoke T3|
|T3|FAIL|Block|
|T3|PASS|Allow|
|Any|Error|Apply documented error policy|



TABLE II 

DIFFERENCE BETWEEN ROUTING VARIANTS 

|T2 verdict|Rejection policy|Mini-pilot policy|
|---|---|---|
|FAIL|Block|Block|
|PASS|Invoke T3|Allow|
|UNSURE|Invoke T3|Invoke T3|



- 2) Evaluate T2. Return BLOCK if it fails. 

- 3) Evaluate T3. Return ALLOW only if its final verdict is PASS; otherwise apply the specified rejection or error policy. 

Later stages are not invoked after an earlier rejection. Thus, the auditing depth varies through early termination even though surviving requests must reach the final auditor. 

## _E. Early Acceptance Is a Different Policy_ 

The earlier five-sample mini-pilot audit describes a different rule: a T2 PASS immediately allows execution, while only UNSURE escalates to T3. Table II distinguishes the two policies. 

These policies have different authorization properties and must not be treated as interchangeable. The code revision 

The supplied primary evaluation contains 580 labeled requests: 330 attacks and 250 benign examples. The description includes direct injections and indirect injections in simulated emails and documents. 

A separate five-sample mini-pilot contains three benign examples and two attacks. Those results are not pooled with the 580-request summary. 

The original manuscript describes the primary set as held out after diagnostic prompt development. However, dataset construction records, sample-level provenance, and tuning history were not supplied for independent inspection here. Held-out status therefore requires confirmation from those artifacts. 

A reproducible release should describe label assignment, template reuse, duplicate removal, and any overlap with development examples. These details determine how broadly the reported rates can be interpreted. 

## _B. Strategies_ 

The supplied manuscript describes: 

- LightweightOnly: T2 supplies the final decision. 

- DeepOnly: T3 supplies the final decision. 

- DeterministicDeep: T1 precedes T3. 

- LightweightDeep: T2 precedes T3. 

- FullCascade: T1 and T2 precede T3. 

Complete security counts are available for three strategies. Runtime summaries are available for three, partially overlapping strategies. Missing results are not reconstructed. 

For standalone lightweight evaluation, the mapping from UNSURE to the final action must be stated. Changing that mapping changes the evaluated operating point even when raw model outputs are unchanged. 

## _C. Reported Runtime Configuration_ 

The original manuscript reports execution through Ollama on an Apple M5 system with 16 GB unified memory, using a Llama 3.2 lightweight guard and a Llama 3 deep guard. It also states INT4 quantization, temperature zero, and sequential strategy execution. 

These details are reported configuration, not independently verified runtime metadata. In particular, the software version string 0.40.6 must be checked against the machine that produced the primary results. 

Model tags should be supplemented with resolved identifiers and metadata establishing the weights and quantization used. Temperature zero documents a decoding setting but does not establish identical execution across all runtime and hardware configurations. 

TABLE III 

REPORTED CONFUSION COUNTS AND BYPASS RATES 

|Strategy|TP|FN|FP<br>TN|ASR (%)|
|---|---|---|---|---|
|LightweightOnly|178|152|0 250|46.06|
|DeepOnly|247|83|0 250|25.15|
|FullCascade|290|40|0 250|12.12|



### TABLE IV 

REPORTED DEEP CALLS AND END-TO-END LATENCY 

|Strategy|Deep calls|Mean latency<br>(ms)|p95 latency (ms)|
|---|---|---|---|
|DeepOnly|580|358.24|437.33|
|LightweightDeep|402|568.66|890.89|
|FullCascade|386|509.94|712.35|



## _D. Metric Definitions_ 

Let TP denote attacks blocked, FN attacks allowed, FP benign requests blocked, and TN benign requests allowed. 

The reported attack success rate is a filter-bypass rate: 







Deep-call reduction relative to DeepOnly is: 



where _N_ 3 is the number of deep invocations and _N_ is the number of requests. 

Reported latency is interpreted as elapsed time to a final strategy decision. Fair comparison requires consistent timing boundaries, warm-up, execution order, and handling of unsuccessful requests. 

## _E. Sequential Latency Model_ 

Let _t_ 1, _t_ 2, and _t_ 3 be stage durations, with indicators _I_ 2 and _I_ 3 specifying whether T2 and T3 are invoked. A simplified per-request model is: 



This model explains why invocation savings need not produce a speed improvement. Requests reaching T3 also pay for preceding checks. Measuring the complete pipeline is consistent with the system-level latency perspective in [3]. 

## VI. RESULTS 

## _A. Security Performance_ 

Table III reproduces the supplied counts and includes false negatives derived from the stated 330 attacks. All three reported strategies allow the 250 benign examples. 

FullCascade blocks 43 more attacks than DeepOnly and 112 more than LightweightOnly. Relative to DeepOnly, the aggregate bypass count decreases from 83 to 40. 

This corresponds to approximately a 51.8% relative reduction in bypasses and a 13.03-percentage-point reduction in ASR. The relative comparison describes the fraction of DeepOnly bypasses removed in aggregate; the percentage-point comparison describes the change across all attacks. 

These are descriptive results for the supplied evaluation set. No inference of population-wide superiority is made without additional information about sampling and evaluation design. 

## _B. False Positives_ 

No false positives are reported among 250 benign requests. The observed FPR is therefore zero for the strategies in Table III. 

This does not establish a zero underlying error probability. Under an independent Bernoulli-trial model, the one-sided 95% upper bound after zero events in _n_ trials satisfies: 



For _n_ = 250, this is approximately 1.19%. The interpretation depends on the sampling assumptions; repeated templates need not behave like independent examples. 

The observation also concerns benign blocking only. It does not demonstrate unchanged task-completion quality or unchanged user-visible responsiveness. 

## _C. Deep Invocations and Latency_ 

Table IV presents the supplied resource and latency summaries. 

FullCascade avoids 194 deep calls relative to DeepOnly, approximately a 33.4% reduction. It makes 16 fewer deep calls than LightweightDeep. 

These are invocation-count savings, not direct measurements of energy, total tokens, monetary cost, or accelerator time. Preliminary stages also consume resources. 

FullCascade’s reported mean latency is 151.70 ms higher than DeepOnly, approximately a 42.3% increase. Its p95 is also higher. The evaluation therefore does not support a claim that the cascade is faster than DeepOnly. 

Relative to LightweightDeep, FullCascade has a lower mean by 58.72 ms and a lower p95 by 178.54 ms. This is consistent with early rejection avoiding downstream work, although repeated, controlled runs are needed for stronger causal attribution. 

## _D. Attribution of Additional Blocks_ 

The difference between 290 and 247 true positives is 43. Marginal totals alone do not establish that exactly 43 DeepOnly failures were corrected without any regressions. 

Let _A_ contain attacks blocked by FullCascade but allowed by DeepOnly, and let _B_ contain attacks showing the reverse outcome. The totals imply: 



Identifying the two set sizes separately requires paired decisions. If identical deep verdicts were reused and earlier stages could only add rejections, then _B_ would be empty by construction. Separate model runs or changed inputs can invalidate that assumption. 

The original draft reports 43 corrected cases. That paired claim should be linked to sample identifiers and logs rather than inferred from the difference in aggregate totals. 

## _C. Interpreting Deterministic Pruning_ 

The 16-call difference between LightweightDeep and FullCascade does not alone establish that T1 blocked exactly 16 total requests. 

Some requests rejected by T1 might also have been rejected by T2 and would not have reached T3 under either strategy. The relevant quantity is the number of T1 rejections that would otherwise have continued. 

Attributing the invocation reduction to specific requests therefore requires paired routing evidence. Aggregate totals establish a net difference, not every underlying stage decision. 

## _D. Combining Screening With Authorization_ 

A classifier’s PASS does not grant a tool permission that it should not possess. Scoped access and approval-gated elevation address privilege boundaries even when maliciousness classification is uncertain [5]. 

Likewise, memory authorization can depend on the lineage of derived information rather than the apparent harmlessness of a proposed operation [4]. ASCP should therefore be understood as a filtering component, not a replacement for every authorization mechanism. 

An integration with such controls would require its own implementation and evaluation. It is not demonstrated by the present results. 

## _E. Operational Failure Handling_ 

## VII. DISCUSSION 

## _A. A Tradeoff Rather Than Universal Superiority_ 

The supplied results identify a potentially useful operating point: more attacks are blocked and fewer deep calls are made, with no additional observed benign blocks in the evaluated set. 

However, the cascade is slower than DeepOnly in the reported timing summary. A deployment prioritizing attack rejection may accept this overhead, whereas a latency-sensitive application may prefer another configuration. The appropriate choice depends on requirements that the current benchmark does not determine. 

This interpretation is consistent with treating runtime safety, authorization, and responsiveness as separate design concerns [1], [3], [5]. 

## _B. Benign Traffic and Deployment Mixtures_ 

Under rejection routing, benign requests that pass earlier checks still reach T3. Consequently, early stages can add work to a substantial portion of legitimate traffic. 

The evaluation contains 330 attacks out of 580 requests. That mixture should not automatically be treated as a production distribution. A deployment with a different benign-to-attack ratio can exhibit different average latency and deep-call savings. 

Deployment projections should therefore state their traffic assumptions and, where possible, report stage behavior separately for benign and attack requests. 

A complete deployment must define behavior for timeouts, unavailable models, malformed responses, and parser failures. 

Blocking on every error can preserve a restrictive authorization posture while reducing availability. Allowing on error can preserve availability while weakening enforcement. These choices should be explicit and reported separately from ordinary model classifications. 

Failure-path testing is therefore part of evaluating the implemented system, not merely a formatting or logging detail. 

## VIII. CONCLUSION 

ASCP organizes tool-call screening into deterministic, lightweight, and deep stages. Under rejection routing, earlier stages can block requests, while surviving requests receive a final deep audit. 

The supplied 580-request summary reports 290 blocked attacks for FullCascade and 247 for DeepOnly, with no observed false positives among 250 benign requests. FullCascade uses 386 deep calls rather than 580. 

These gains occur alongside higher reported mean latency than DeepOnly. The central finding is therefore a tradeoff between observed attack rejection, deep-call frequency, and sequential response time, not a universal speed improvement. 

Further work will verify the artifact provenance, resolve the routing-version distinction, publish paired decisions, and repeat controlled runtime measurements. End-to-end agent experiments and adaptive testing are needed before extending the findings from filter decisions to demonstrated protection of deployed workflows. 

REFERENCES 

- [1] H. Wang, C. M. Poskitt, and J. Sun, “AgentSpec: Customizable runtime enforcement for safe and reliable LLM agents,” in _Proc. 2026 IEEE/ACM 48th International Conference on Software Engineering (ICSE)_ , 2026, doi: https://doi.org/10.1145/3744916.3764546. 

- [2] A. Chhabra, S. Datta, S. K. Nahin, and P. Mohapatra, “Agentic AI security: Threats, defenses, evaluation, and open challenges,” _IEEE Access_ , vol. 14, pp. 49455–49482, 2026, doi: https://doi.org/10.1109/ACCESS.2026. 3675554. 

- [3] G. Park, S. Lee, and Y. Park, “Minimizing response latency in LLMbased agent systems: A comprehensive survey,” _IEEE Access_ , vol. 14, pp. 26140–26168, 2026, doi: https://doi.org/10.1109/access.2026.3664226. 

- [4] V. Sangaraju and S. Vissa, “Lineage-aware memory governance: A derivation-gated framework for privacy-preserving column-level access control in enterprise AI agents,” _IEEE Access_ , 2026, doi: https://doi.org/ 10.1109/ACCESS.2026.3730363. 

- [5] G. Singh and V. K. Madisetti, “MCP-Secure: A runtime access control layer for privilege-aware LLM agent tooling,” _IEEE Open Journal of the Computer Society_ , vol. 7, pp. 504–513, 2026, doi: https://doi.org/10.110 9/OJCS.2026.3664314. 

