# Workload-Aware Adaptive Dynamic Oversight for Agentic AI Systems 

Snehal Jagtap, Vikas Kumar, and Shamsul Haque 

_Department of Computer Science & Engineering_ 

_Chhatrapati Shivaji Maharaj University_ 

Navi Mumbai, Maharashtra, India 

snehaljagtap453@gmail.com 

**_Abstract_ —Agentic AI systems can execute multi-step workflows with limited direct supervision, creating an oversight problem that differs from conventional human-in-the-loop (HITL) systems. Fixed approval gates can increase latency and place substantial demand on human reviewers, while reducing human involvement can leave unsafe actions insufficiently checked. This paper presents the Workload-Aware Adaptive Dynamic Intervention Framework (WA-DIF), which extends dynamic intervention by treating human oversight capacity as a time-varying system resource. WA-DIF combines a Contextual Confidence Score (CCS) with a workload-aware controller that adjusts routing thresholds using the active operator queue and provides an agentic self-reflection path when human capacity is constrained. The framework is evaluated on a reported synthetic benchmark of 1,000 multi-step automation tasks under burst workload conditions against an unconstrained autonomous agent and a static Dynamic Intervention Framework (DIF). The reported results show task success rates of 81.4%, 88.2%, and 96.8% for the three architectures, respectively, with corresponding dangerthrough rates of 18.6%, 11.8%, and 3.2%. WA-DIF also reports lower human escalation and rubber-stamping rates than static DIF. These results are limited to the synthetic evaluation and do not constitute validation with human subjects or production telemetry. The study therefore treats WA-DIF as a workloadaware oversight architecture whose reported behavior requires further empirical validation.** 

**_Index Terms_ —Agentic AI, Human-in-the-Loop, Dynamic Oversight, Automation Bias, Workload Calibration, AI Safety, Learning to Defer.** 

## I. INTRODUCTION 

Agentic artificial intelligence systems increasingly combine planning, reasoning, tool use, and multi-step execution. Unlike conventional conversational systems, an agent can generate an action, observe the resulting state, and continue through a workflow with limited direct human intervention. This autonomy creates a safety problem at the execution layer: an incorrect or unauthorized action can propagate across several dependent steps before a human has an opportunity to intervene. 

Traditional human-in-the-loop (HITL) designs address this problem by inserting approval checkpoints. However, requiring synchronous approval for every potentially consequential action can introduce latency and make human attention the bottleneck of the system. Kumar and Singh proposed the Dynamic Intervention Framework (DIF), which routes agent decisions among autonomous execution, asynchronous audit, 

and synchronous human escalation using a composite Contextual Confidence Score [1]. This formulation makes human intervention selective rather than universal. 

The remaining limitation is that selective oversight can still generate a human workload that is treated as externally unlimited. Under bursty workloads, a static routing policy can produce a queue of escalations that competes for the same finite human attention. Research on automation bias and human oversight indicates that people may rely heavily on algorithmic recommendations and may fail to correct inaccurate recommendations, particularly when attention is constrained [2], [3]. Recent work on agent oversight and learning to defer similarly frames human capacity as a resource rather than an unlimited oracle [4], [5]. 

This paper therefore presents the Workload-Aware Adaptive Dynamic Intervention Framework (WA-DIF). The central design change is to make the routing policy responsive not only to action confidence but also to current human workload. When the human queue increases, the controller changes the routing thresholds so that borderline actions are less likely to create additional synchronous interventions, while high-stakes low-confidence cases remain candidates for human escalation. A secondary agentic self-reflection path is used for cases that can be reconsidered without consuming immediate human capacity. 

The paper makes three contributions: 

- 1) It formulates a workload-aware routing controller that incorporates active queue load into intervention thresholds. 

- 2) It integrates an agentic self-reflection fallback for periods in which human capacity is constrained. 

- 3) It evaluates the proposed architecture on a 1,000-task synthetic benchmark and compares it against unconstrained agent execution and a static DIF baseline. 

## II. RELATED WORK 

## _A. Agentic AI and Dynamic Human Oversight_ 

Kumar and Singh describe DIF as a Supervisor-Worker architecture in which a supervisor evaluates worker actions through a composite confidence score and routes them to autonomous execution, asynchronous audit, or synchronous human escalation [1]. Their formulation provides a useful 

foundation for selective oversight because it explicitly recognizes that human intervention can be allocated rather than applied to every action. WA-DIF retains this routing structure while adding an explicit workload state to the controller. 

## _B. Human Workload, Automation Bias, and Rubber-Stamping_ 

Human oversight does not guarantee correction of an automated system’s errors. Sele and Chugunova reported an online experiment with 292 participants in which participants followed algorithmic recommendations closely and were less likely to intervene on the least accurate recommendations [2]. Parasuraman and Manzey’s review likewise connects automation bias and complacency with attentional demands and competing task load [3]. These findings motivate modeling human review quality as workload-dependent rather than assuming a perfect reviewer. 

## _C. Workload-Constrained Deferral_ 

Learning-to-defer research provides a related formulation in which an AI system decides when to rely on a human expert. Alves et al. explicitly incorporate human work-capacity constraints into cost-sensitive deferral [4]. Zhang et al. further model workload-varying human performance in FALCON using a constrained decision process [5]. Turan’s preprint applies the same resource-allocation perspective directly to agent oversight, arguing that escalation itself consumes a finite human capacity and that excessive escalation can reduce realized safety [6]. 

WA-DIF adapts the workload-aware idea to the routing structure of DIF, using queue load as an explicit controller signal and retaining autonomous, asynchronous, and synchronous pathways. 

III. METHODOLOGY 

## _A. Architecture Overview_ 

WA-DIF separates action generation from oversight routing. A Worker Agent produces a proposed action within a multistep task. A Supervisor computes a Contextual Confidence Score (CCS), after which a workload-aware controller selects autonomous execution, asynchronous audit, synchronous human escalation, or the self-reflection fallback. The active operator queue _Q_ ( _t_ ) feeds back into the controller so that the routing policy can react to changing review demand. 

## _B. Contextual Confidence Score_ 

The source manuscript defines CCS as a linear combination of generation confidence and semantic alignment: 



where _P_ logits( _at|st_ ) denotes normalized generation probability given current state _st_ , _S_ semantic( _at, g_ ) represents semantic similarity between proposed action _at_ and goal _g_ , and _α ∈_ [0 _,_ 1] is a balancing parameter. 

## _C. Queue State Dynamics and Adaptive Thresholds_ 

Let _Q_ ( _t_ ) _∈_ [0 _, Q_ max] represent the length of the human review queue at discrete time _t_ . The dynamics of _Q_ ( _t_ ) follow a discrete-time queuing recurrence: 



where _λ_ esc( _t_ ) is the arrival rate of escalated tasks and _µ_ rev( _t_ ) is the human completion rate. 

The controller dynamically computes upper threshold _T_ high( _t_ ) and lower threshold _T_ low( _t_ ): 



Here _λ, µ >_ 0 dictate adaptation sensitivity, _β ≥_ 1 introduces non-linear threshold damping during severe queue congestion, and _T_ min guarantees an absolute lower floor below which actions must undergo review regardless of workload. 

## _D. Human Review Quality and Fatigue Modeling_ 

Human review quality is modeled as a function of cumulative active workload _l_ ( _t_ ): 



where _C_ represents threshold human cognitive capacity, _γ_ is the degradation coefficient, and _r_ min represents baseline accuracy under severe fatigue. The probability _P_ stamp that a human reviewer uncritically approves an erroneous action (rubber-stamping) increases proportionally with fatigue: 



## _E. Adaptive Routing Controller Algorithm_ 



<!-- Start of picture text -->
Autonomous<br>Execution<br>Worker Agent Supervisor<br>Asynchronous Audit<br>Multi-step plan CCS<br>Human Escalation<br>WA-DIF Controller<br>Adaptive thresholds<br>Q ( t )<br><!-- End of picture text -->

Fig. 1. Conceptual architecture of the Workload-Aware Adaptive Dynamic Intervention Framework. 

Algorithm 1 summarizes the routing process executed by the WA-DIF controller for each candidate action proposal. 

## IV. SYSTEM IMPLEMENTATION AND INTEGRATION 

To enable practical evaluation, WA-DIF is implemented as an asynchronous microservice layer operating between the LLM reasoning core and the environment tool execution engines. Figure 2 illustrates the system interface deployment. The Supervisor module evaluates action logits directly from the model inference stream while computing cosine semantic embedding distances relative to goal states. Queue telemetry _Q_ ( _t_ ) is synchronized via a distributed Redis store. 

**Algorithm 1** Workload-Aware Adaptive Routing Controller 

- **Require:** _at, st, g, T_ high<sup>base</sup><sup>_, T_</sup> low<sup>base</sup><sup>_, Q_(</sup><sup>_t_)</sup><sup>_, Q_max</sup> **Ensure:** Routing Decision _D ∈ {_ Auto _,_ Audit _,_ SelfReflect _,_ Human Esc _}_ 

- 1: _CCS_ ( _at_ ) _← αP_ logits( _at | st_ ) + (1 _− α_ ) _S_ semantic( _at, g_ ) 2: _T_ high( _t_ ) _← T_ high<sup>base+</sup><sup>_λ_(</sup><sup>_Q_(</sup><sup>_t_)</sup><sup>_/Q_max)</sup><sup>_β_</sup> 3: _T_ low( _t_ ) _←_ max( _T_ min _, T_ low<sup>base</sup><sup>_−µ_(</sup><sup>_Q_(</sup><sup>_t_)</sup><sup>_/Q_max)</sup><sup>_β_)</sup> 4: **if** _CCS_ ( _at_ ) _≥ T_ high( _t_ ) **then** 5: **return** _D ←_ Autonomous Execution 6: **else if** _T_ low( _t_ ) _≤ CCS_ ( _at_ ) _< T_ high( _t_ ) **then** 7: **if** _Q_ ( _t_ ) _/Q_ max _> θ_ overload **then** 8: **return** _D ←_ Self-Reflection Fallback 9: **else** 

- 10: **return** _D ←_ Asynchronous Audit 11: **end if** 12: **else** 

- 13: **return** _D ←_ Human Escalation 

14: **end if** 

boundaries ( _T_ high = 0 _._ 85, _T_ low = 0 _._ 50) independent of operator queue length [1]. 

- **WA-DIF (Proposed):** Integrates active queue feedback _Q_ ( _t_ ) into adaptive threshold scaling combined with agentic self-reflection under overload conditions. 

## _C. Evaluation Metrics_ 

- **Task Success Rate (%):** Percentage of workflows successfully completed without fatal failure or incorrect final state. 

- **Human Escalation Rate (%):** Proportion of execution steps routed to synchronous human review. 

- **Rubber-Stamping Rate (%):** Percentage of invalid action proposals erroneously approved by human reviewers under simulated cognitive fatigue. 

- **Danger-Through Rate (%):** Percentage of unsafe or incorrect execution steps that executed autonomously or were improperly approved. 

## VI. RESULTS AND DISCUSSION 

**Application Layer:** Multi-Agent Task Orchestrator (Financial, Code, Ops) 



<!-- Start of picture text -->
Supervisor & Governance Layer:  CCS Evaluator  |<br>Redis Queue  Q ( t )  |  Adaptive Controller<br>Execution & Intervention Layer:  Tool API  |<br>LLM Self-Reflect Path  |  Operator Console<br><!-- End of picture text -->

Fig. 2. Layered deployment architecture of the WA-DIF microservice runtime. 

## _A. Comparative Overall Performance_ 

Table I provides the quantitative benchmark results across all 1,000 evaluated tasks under severe burst workload conditions. 

### TABLE I 

PERFORMANCE COMPARISON UNDER BURST WORKLOAD CONDITIONS 

|**Architecture**<br>**S**|**uccess (%) **|**Escalation (%) **|**Rubber-Stamping (%) **|**Danger-Through (%)**|
|---|---|---|---|---|
|Unconstrained Agent|81.4|0.0|0.0|18.6|
|Static DIF [1]|88.2|24.5|41.2|11.8|
|**WA-DIF (Proposed)**|**96.8**|**11.2**|**4.1**|**3.2**|



## V. EXPERIMENTAL SETUP 

## _A. Synthetic Evaluation Dataset_ 

The evaluation uses a benchmark of 1,000 multi-step automation tasks divided across three primary operational domains: 

- **Financial Transaction Processing (350 tasks):** Highstakes database updates, wire transfer routing, and account reconciliation. 

- **Code Refactoring and Deployment (350 tasks):** Automated dependency updates, API refactoring, and CI/CD script execution. 

- **Customer Operations (300 tasks):** Ticket resolution, refund issuance, and automated database queries. 

Workload bursts are injected by applying a non-homogeneous Poisson arrival process where task submission rates triple during peak window intervals. 

## _B. Experimental Baselines_ 

The framework is evaluated against two comparison baselines: 

- **Unconstrained Autonomous Agent:** Executes generated plans directly without supervisory evaluation or human intervention. 

- **Static Dynamic Intervention Framework (Static DIF):** Employs standard supervisor routing with fixed threshold 

Under burst conditions, Static DIF generates severe escalation bottlenecks. As _Q_ ( _t_ ) approaches capacity, simulated human operators experience elevated cognitive load _l_ ( _t_ ), increasing the rubber-stamping rate to 41.2%. Consequently, invalid actions pass through human approval, resulting in an 11.8% danger-through rate. 

In contrast, WA-DIF dynamically raises _T_ high( _t_ ) and lowers _T_ low( _t_ ), filtering intermediate-risk actions away from human queues and triggering self-reflection fallback. This dynamic shift reduces human escalation to 11.2%, lowers rubberstamping to 4.1%, and achieves a task success rate of 96.8%. 

## _B. Domain-Specific Breakdown Analysis_ 

To evaluate safety across varying risk profiles, task performance was stratified by domain category. Table II reports domain-specific success and escalation metrics. 

The domain breakdown demonstrates that WA-DIF maintains high safety bounds even in financial workflows, where baseline error rates are highest due to complex policy constraints. 

## _C. Sensitivity Analysis of Workload Adaptation_ 

We investigated controller stability across different queue sensitivity parameters _λ_ and _µ_ . Figure 3 illustrates the relationship between threshold scaling factors and realized dangerthrough rates. 

TABLE II 

DOMAIN-STRATIFIED EXECUTION METRICS ACROSS ARCHITECTURES 



<!-- Start of picture text -->
Domain Architecture Success (%) Escalation (%) Danger-Through (%)<br>Financial Transactions Unconstrained 74.2 0.0 25.8<br>Static DIF [1] 82.6 31.2 15.4<br>WA-DIF 94.8 15.4 4.2<br>Code Refactoring Unconstrained 83.1 0.0 16.9<br>Static DIF [1] 89.4 22.1 10.1<br>WA-DIF 97.4 10.2 2.6<br>Customer Operations Unconstrained 87.3 0.0 12.7<br>Static DIF [1] 93.0 19.8 9.2<br>WA-DIF 98.3 7.8 2.4<br>Danger-Through Rate<br>10<br>5<br>0<br>0 . 1 0 . 2 0 . 3 0 . 4<br>Adaptation Coefficients ( λ = µ )<br>Danger-Through(%)Rate<br><!-- End of picture text -->

Fig. 3. Sensitivity of danger-through rate relative to controller adaptation coefficients _λ_ and _µ_ . 

Optimal performance occurs in the range _λ, µ ∈_ [0 _._ 15 _,_ 0 _._ 25]. Overly aggressive adaptation ( _λ, µ >_ 0 _._ 35) excessively restricts human intervention during peak queues, causing risky actions to bypass review. Conversely, under-sensitive scaling ( _λ, µ <_ 0 _._ 10) approaches static DIF behavior, triggering operator fatigue. 

Future research will focus on validating operator fatigue models through controlled human-subject experiments, incorporating real-time EEG and physiological cognitive monitoring into controller feedback, and testing WA-DIF across enterprise multi-agent production pipelines. 

## ACKNOWLEDGMENT 

The authors express gratitude to the research advisors and peer reviewers whose feedback supported the conceptualization and refinement of this architecture. 

## REFERENCES 

- [1] M. Kumar and D. Singh, ”Balancing autonomy and oversight in reliable agentic artificial intelligence through adaptive human interaction architectures,” _Discover Artificial Intelligence_ , vol. 6, art. no. 709, 2026. DOI: 10.1007/s44163-026-01373-2 

- [2] D. Sele and M. Chugunova, ”Putting a human in the loop: Increasing uptake, but decreasing accuracy of automated decision-making,” _PLOS ONE_ , vol. 19, no. 2, art. no. e0298037, 2024. DOI: 10.1371/journal.pone.0298037 

- [3] R. Parasuraman and D. H. Manzey, ”Complacency and bias in human use of automation: An attentional integration,” _Human Factors_ , vol. 52, no. 3, pp. 381–410, 2010. DOI: 10.1177/0018720810376055 

- [4] J. V. Alves, D. Leit˜ao, S. Jesus, M. O. P. Sampaio, J. Li´ebana, P. Saleiro, M. A. T. Figueiredo, and P. Bizarro, ”Cost-Sensitive Learning to Defer to Multiple Experts with Workload Constraints,” _Transactions on Machine Learning Research_ , 2024. [Online]. Available: https://openreview.net/ forum?id=vS8pX97X41 

- [5] Z. Zhang, C. C. Nguyen, D. Rosewarne, K. Wells, and G. Carneiro, ”Fatigue-Aware Learning to Defer via Constrained Optimisation,” _arXiv preprint arXiv:2604.00904_ , 2026. [Online]. Available: https://arxiv.org/ abs/2604.00904 

- [6] E. Turan, ”Oversight Has a Capacity: Calibrating Agent Guards to a Subjective, Fatiguing Human,” _arXiv preprint arXiv:2606.08919_ , 2026. [Online]. Available: https://arxiv.org/abs/2606.08919 

## VII. LIMITATIONS AND RISK ANALYSIS 

While WA-DIF improves synthetic benchmark metrics, several critical limitations must be addressed prior to real-world operational deployment: 

- 1) **Synthetic Fatigue Dynamics:** The human fatigue law _r_ ( _l_ ( _t_ )) represents a mathematical approximation and has not been validated through empirical human-subject trials or biometric cognitive load telemetry. 

- 2) **Failure Amplification in Self-Reflection:** The selfreflection fallback relies on model self-critique. If an LLM exhibits systemic reasoning bias, self-reflection may reinforce initial errors rather than correct them. 

- 3) **Parameter Calibration Dependence:** System performance depends heavily on accurate calibration of _α, λ, µ,_ and _T_ min. Suboptimal calibration can lead to unsafe dynamic threshold expansion. 

## VIII. CONCLUSION AND FUTURE WORK 

This paper presented WA-DIF, a workload-aware extension of dynamic intervention for agentic AI systems. By treating human review capacity as a finite, time-varying resource, WA-DIF adjusts decision routing thresholds based on realtime operator queue states. In a synthetic evaluation of 1,000 multi-step automation tasks under burst workloads, WA-DIF achieved a task success rate of 96.8% and reduced dangerthrough rates to 3.2%, compared to 88.2% success and 11.8% danger-through for static DIF. 

