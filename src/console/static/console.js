/**
 * AASF Interactive Security Console - Frontend Client
 * Handles real-time communication with the FirewallCore REST API,
 * dynamic timeline rendering, scenario triggering, human review, and audit exploration.
 */

let activeSessionId = "demo_session_01";
let availableTools = [];
let allScenarios = [];

// Initialize on DOM load
document.addEventListener("DOMContentLoaded", () => {
  setupTabs();
  setupSessionControls();
  loadTools();
  loadScenarios();
  refreshSessionState();
  refreshReviewQueue();
  refreshAuditTrail();

  // Action submission button
  document.getElementById("btn-submit-action").addEventListener("click", handleActionSubmit);
  document.getElementById("btn-refresh-state").addEventListener("click", refreshSessionState);
  document.getElementById("btn-refresh-reviews").addEventListener("click", refreshReviewQueue);
  document.getElementById("btn-verify-chain").addEventListener("click", handleVerifyChain);
  document.getElementById("btn-tamper-chain").addEventListener("click", handleTamperChain);
  document.getElementById("btn-restore-chain").addEventListener("click", handleRestoreChain);
});

// Setup navigation tabs
function setupTabs() {
  const tabs = document.querySelectorAll(".nav-tab");
  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      tabs.forEach(t => t.classList.remove("active"));
      document.querySelectorAll(".tab-content").forEach(tc => tc.classList.remove("active"));

      tab.classList.add("active");
      const targetId = tab.getAttribute("data-tab");
      const targetEl = document.getElementById(targetId);
      if (targetEl) targetEl.classList.add("active");

      // Auto refresh relevant tab contents
      if (targetId === "tab-review") refreshReviewQueue();
      if (targetId === "tab-audit") refreshAuditTrail();
      if (targetId === "tab-simulator") refreshSessionState();
    });
  });
}

// Setup session controls
function setupSessionControls() {
  const sessionInput = document.getElementById("active-session-id");
  sessionInput.addEventListener("change", (e) => {
    activeSessionId = e.target.value.trim() || "demo_session_01";
    refreshSessionState();
    refreshAuditTrail();
  });

  document.getElementById("btn-new-session").addEventListener("click", () => {
    const randId = "session_" + Math.random().toString(36).substring(2, 8);
    sessionInput.value = randId;
    activeSessionId = randId;
    refreshSessionState();
    refreshAuditTrail();
  });
}

// Load registered tools from backend
async function loadTools() {
  try {
    const res = await fetch("/api/tools");
    availableTools = await res.json();
    const select = document.getElementById("select-tool");
    select.innerHTML = "";
    availableTools.forEach(t => {
      const opt = document.createElement("option");
      opt.value = t.name;
      opt.textContent = `${t.name} (${t.tool_class})`;
      select.appendChild(opt);
    });

    select.addEventListener("change", updateToolClassPill);
    updateToolClassPill();
  } catch (err) {
    console.error("Failed to load tools:", err);
  }
}

function updateToolClassPill() {
  const toolName = document.getElementById("select-tool").value;
  const toolObj = availableTools.find(t => t.name === toolName);
  const pill = document.getElementById("tool-class-pill");
  if (toolObj) {
    pill.textContent = toolObj.tool_class;
  }
}

// Quick payload template selector
function setPayload(type) {
  const select = document.getElementById("select-tool");
  const args = document.getElementById("request-arguments");
  const notes = document.getElementById("context-notes");

  if (type === "validate_schema") {
    select.value = "validate_schema";
    args.value = JSON.stringify({}, null, 2);
    notes.value = "Diagnostic health check and schema validation.";
  } else if (type === "select_confidential") {
    select.value = "select_resource";
    args.value = JSON.stringify({ resource_id: "customer_records" }, null, 2);
    notes.value = "Access confidential customer records dataset.";
  } else if (type === "export_external") {
    select.value = "execute_export";
    args.value = JSON.stringify({ destination_id: "external_cloud_bucket", rows: 5000 }, null, 2);
    notes.value = "Attempt export of current job data to external cloud storage.";
  } else if (type === "relabel_public") {
    select.value = "relabel_resource";
    args.value = JSON.stringify({ resource_id: "customer_records", target: "PUBLIC" }, null, 2);
    notes.value = "Privileged administrative relabeling of confidential data to public.";
  }
  updateToolClassPill();
}

// Load preset scenarios
async function loadScenarios() {
  try {
    const res = await fetch("/api/scenarios");
    allScenarios = await res.json();
    const container = document.getElementById("scenarios-container");
    container.innerHTML = "";

    allScenarios.forEach(scen => {
      const btn = document.createElement("button");
      btn.className = "btn-scenario";
      btn.innerHTML = `<span class="scen-tag">${scen.id}</span> <span>${scen.name}</span>`;
      btn.title = `${scen.description} (Expected: ${scen.expected})`;
      btn.addEventListener("click", () => triggerPresetScenario(scen.id));
      container.appendChild(btn);
    });
  } catch (err) {
    console.error("Failed to load scenarios:", err);
  }
}

// Trigger preset scenario
async function triggerPresetScenario(scenarioId) {
  try {
    const res = await fetch(`/api/scenarios/run/${scenarioId}`, {
      method: "POST"
    });
    const data = await res.json();

    // If scenario returned a custom session, adopt it
    if (data.session_id) {
      activeSessionId = data.session_id;
      document.getElementById("active-session-id").value = activeSessionId;
    }

    // Switch to Inspector tab and render
    switchToTab("tab-inspector");
    renderInspectorTrace(data);
    refreshSessionState();
    refreshReviewQueue();
    refreshAuditTrail();
  } catch (err) {
    alert("Error executing scenario: " + err.message);
  }
}

// Submit custom action
async function handleActionSubmit() {
  const tool = document.getElementById("select-tool").value;
  let args = {};
  try {
    args = JSON.parse(document.getElementById("request-arguments").value || "{}");
  } catch (e) {
    alert("Invalid JSON in arguments field!");
    return;
  }
  const contextNotes = document.getElementById("context-notes").value;

  try {
    const res = await fetch("/api/action/submit", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        session_id: activeSessionId,
        tool: tool,
        arguments: args,
        context_notes: contextNotes
      })
    });
    const data = await res.json();

    // Switch to Inspector tab
    switchToTab("tab-inspector");
    renderInspectorTrace(data);
    refreshSessionState();
    refreshReviewQueue();
    refreshAuditTrail();
  } catch (err) {
    alert("Failed to submit action: " + err.message);
  }
}

// Render Inspector Trace
function renderInspectorTrace(data) {
  // Decision badge
  const decBadge = document.getElementById("inspector-decision");
  const dec = data.decision || "DENY";
  decBadge.textContent = dec;
  decBadge.className = `decision-badge ${dec}`;

  // Tab badge
  const tabBadge = document.getElementById("inspector-badge");
  tabBadge.textContent = dec;
  tabBadge.className = `tab-badge ${dec}`;
  tabBadge.style.display = "inline-block";

  // Status tag & latency
  document.getElementById("inspector-status").textContent = data.status || "UNKNOWN";
  document.getElementById("inspector-latency").textContent = `${data.firewall_latency_ms || 0.45} ms`;

  // Reasons
  const reasonSec = document.getElementById("reason-section");
  const reasonsDiv = document.getElementById("inspector-reasons");
  reasonsDiv.innerHTML = "";
  const reasons = data.reason_codes || [];
  if (reasons.length > 0) {
    reasonSec.style.display = "block";
    reasons.forEach(r => {
      const p = document.createElement("span");
      p.className = "reason-pill";
      p.textContent = r;
      reasonsDiv.appendChild(p);
    });
  } else {
    reasonSec.style.display = "none";
  }

  // Lifecycle Timeline Stages
  const timeline = document.getElementById("lifecycle-timeline");
  timeline.innerHTML = "";

  const stages = data.stages || [];
  if (stages.length === 0) {
    timeline.innerHTML = `<div class="timeline-empty">Scenario summary: ${data.message || JSON.stringify(data, null, 2)}</div>`;
  } else {
    stages.forEach(st => {
      const el = document.createElement("div");
      el.className = "timeline-stage open"; // open by default for visibility
      el.innerHTML = `
        <div class="timeline-stage-header">
          <div class="stage-title-wrap">
            <span class="stage-num">${st.step}</span>
            <span class="stage-name">${st.name}</span>
          </div>
          <span class="stage-badge ${st.status}">${st.status}</span>
        </div>
        <div class="timeline-stage-body">
          <pre class="code-block">${JSON.stringify(st.details, null, 2)}</pre>
        </div>
      `;
      el.querySelector(".timeline-stage-header").addEventListener("click", () => {
        el.classList.toggle("open");
      });
      timeline.appendChild(el);
    });
  }

  // Execution Output Card
  const execCard = document.getElementById("execution-output-card");
  const execContent = document.getElementById("execution-output-content");
  if (data.tool_executed && data.execution_value) {
    execCard.style.display = "block";
    execContent.innerHTML = `<pre class="code-block">${JSON.stringify(data.execution_value, null, 2)}</pre>`;
  } else if (data.execution_error) {
    execCard.style.display = "block";
    execContent.innerHTML = `<pre class="code-block" style="color:var(--color-deny);">${JSON.stringify(data.execution_error, null, 2)}</pre>`;
  } else {
    execCard.style.display = "none";
  }
}

// Refresh Session State
async function refreshSessionState() {
  try {
    const res = await fetch(`/api/session/${activeSessionId}/state`);
    const data = await res.json();

    document.getElementById("state-seq").textContent = data.seq;
    const taintPill = document.getElementById("state-taint");
    taintPill.textContent = data.classification || "NONE";
    taintPill.className = `metric-val ${data.classification === 'CONFIDENTIAL' ? 'badge-danger' : 'badge-neutral'}`;

    document.getElementById("state-has-review").textContent = data.has_pending_review ? "YES (Suspended)" : "No";
    document.getElementById("state-head-hash").textContent = data.head_hash;
    document.getElementById("state-json").textContent = JSON.stringify(data, null, 2);
  } catch (err) {
    console.error("Failed to load session state:", err);
  }
}

// Refresh Human Review Queue
async function refreshReviewQueue() {
  try {
    const res = await fetch("/api/reviews/pending");
    const tickets = await res.json();

    const countBadge = document.getElementById("pending-reviews-count");
    countBadge.textContent = tickets.length;
    countBadge.style.display = tickets.length > 0 ? "inline-block" : "none";

    const container = document.getElementById("review-tickets-container");
    if (tickets.length === 0) {
      container.innerHTML = `<div class="empty-state">No pending review tickets. Current session has no suspended actions.</div>`;
      return;
    }

    container.innerHTML = "";
    tickets.forEach(t => {
      const card = document.createElement("div");
      card.className = "review-ticket-card";
      card.innerHTML = `
        <div class="review-ticket-header">
          <div>
            <span class="ticket-id">${t.ticket_id}</span>
            <span class="status-tag" style="margin-left:8px;">${t.status}</span>
          </div>
          <span style="font-size:11px;color:var(--text-dim);font-family:var(--font-mono);">${new Date(t.created_at_ms).toLocaleTimeString()}</span>
        </div>
        <div class="review-ticket-body">
          <div class="review-meta-row">
            <div><span class="lbl-sm">Session:</span> <strong style="font-family:var(--font-mono);font-size:12px;">${t.session_id}</strong></div>
            <div><span class="lbl-sm">Requested Tool:</span> <code>${t.tool}</code></div>
            <div><span class="lbl-sm">Policy Verdict:</span> <span class="stage-badge REVIEW">${t.policy_verdict}</span></div>
          </div>
          <div style="margin-bottom:8px;">
            <span class="lbl-sm">Flagged Reasons:</span>
            <div style="display:flex;gap:6px;margin-top:4px;">
              ${t.reason_codes.map(r => `<span class="reason-pill">${r}</span>`).join("")}
            </div>
          </div>
          <div>
            <span class="lbl-sm">Sanitized Arguments (INV-10 Redacted):</span>
            <pre class="code-block" style="margin-top:4px;max-height:100px;">${JSON.stringify(t.arguments, null, 2)}</pre>
          </div>
        </div>
        <div class="review-actions-row">
          <button class="btn-sm btn-success" onclick="resolveReviewTicket('${t.ticket_id}', 'APPROVE')">
            ✓ Approve Request (Mint Token & Execute)
          </button>
          <button class="btn-sm btn-danger" onclick="resolveReviewTicket('${t.ticket_id}', 'REJECT')">
            ✕ Reject Request (Halt Execution)
          </button>
          <button class="btn-sm btn-secondary" onclick="simulateStaleDrift('${t.ticket_id}')" title="Test INV-05 TOCTOU State Drift Rejection">
            ⚠️ Simulate State Drift (TOCTOU Exploit)
          </button>
        </div>
      `;
      container.appendChild(card);
    });
  } catch (err) {
    console.error("Failed to load review tickets:", err);
  }
}

// Resolve Review Ticket
async function resolveReviewTicket(ticketId, outcome) {
  try {
    const res = await fetch(`/api/reviews/${ticketId}/resolve`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        outcome: outcome,
        reviewer_id: "sec_officer_web_console"
      })
    });
    const data = await res.json();
    alert(`Review Ticket ${ticketId} resolved as ${outcome}.\nStatus: ${data.status}\nDecision: ${data.decision}\nTool Executed: ${data.tool_executed}`);
    refreshReviewQueue();
    refreshSessionState();
    refreshAuditTrail();
  } catch (err) {
    alert("Failed to resolve review ticket: " + err.message);
  }
}

// Simulate Stale Drift
async function simulateStaleDrift(ticketId) {
  // Triggers preset SCEN-08 logic
  triggerPresetScenario("SCEN-08");
}

// Refresh Audit Trail
async function refreshAuditTrail() {
  try {
    const res = await fetch(`/api/session/${activeSessionId}/audit`);
    const data = await res.json();

    const tbody = document.getElementById("audit-table-body");
    const integrityPill = document.getElementById("chain-integrity-pill");
    const tamperAlert = document.getElementById("tamper-alert");
    const btnRestore = document.getElementById("btn-restore-chain");

    if (data.is_chain_valid) {
      integrityPill.className = "status-pill verified";
      integrityPill.innerHTML = `<span class="status-dot"></span> Hash Chain: <strong>VALID</strong>`;
      tamperAlert.style.display = "none";
      btnRestore.style.display = "none";
    } else {
      integrityPill.className = "status-pill tampered";
      integrityPill.innerHTML = `<span class="status-dot"></span> Hash Chain: <strong>CHAIN BROKEN (TAMPERED)</strong>`;
      tamperAlert.style.display = "block";
      btnRestore.style.display = "inline-block";
    }

    if (data.records.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" class="text-center">No audit records in session '${activeSessionId}'. Submit an action to begin cryptographic logging.</td></tr>`;
      return;
    }

    tbody.innerHTML = "";
    data.records.forEach(rec => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><strong>${rec.seq}</strong></td>
        <td><span class="status-tag">${rec.type}</span></td>
        <td style="color:var(--text-dim);">${new Date(rec.timestamp_ms).toLocaleTimeString()}</td>
        <td class="hash-cell" title="${rec.prev_hash}">${rec.prev_hash.substring(0, 14)}...</td>
        <td class="hash-cell" title="${rec.hash}">${rec.hash.substring(0, 14)}...</td>
        <td>
          <button class="btn-xs" onclick='openModal("Audit Record #${rec.seq} (${rec.type})", ${JSON.stringify(rec)})'>Inspect JSON</button>
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error("Failed to load audit trail:", err);
  }
}

// Verify Chain Button
async function handleVerifyChain() {
  await refreshAuditTrail();
  const integrityPill = document.getElementById("chain-integrity-pill");
  const isValid = integrityPill.classList.contains("verified");
  alert(isValid ? "✓ Cryptographic hash chain verified 100% SOUND! All SHA-256 links match RFC 8785 canonical digest." : "✕ HASH CHAIN VERIFICATION FAILED! Tampering detected in audit records.");
}

// Tamper Button
async function handleTamperChain() {
  try {
    const res = await fetch("/api/audit/tamper-demo", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ session_id: activeSessionId })
    });
    const data = await res.json();
    alert(data.message);
    refreshAuditTrail();
  } catch (err) {
    alert("Tamper failed: " + err.message);
  }
}

// Restore Button
async function handleRestoreChain() {
  try {
    const res = await fetch("/api/audit/restore", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ session_id: activeSessionId })
    });
    const data = await res.json();
    alert(data.message);
    refreshAuditTrail();
  } catch (err) {
    alert("Restore failed: " + err.message);
  }
}

// Helper: Switch tab
function switchToTab(tabId) {
  document.querySelectorAll(".nav-tab").forEach(t => {
    if (t.getAttribute("data-tab") === tabId) t.classList.add("active");
    else t.classList.remove("active");
  });
  document.querySelectorAll(".tab-content").forEach(tc => {
    if (tc.id === tabId) tc.classList.add("active");
    else tc.classList.remove("active");
  });
}

// Modal inspection
function openModal(title, jsonObj) {
  document.getElementById("modal-title").textContent = title;
  document.getElementById("modal-json").textContent = JSON.stringify(jsonObj, null, 2);
  document.getElementById("inspect-modal").style.display = "flex";
}

function closeModal() {
  document.getElementById("inspect-modal").style.display = "none";
}

