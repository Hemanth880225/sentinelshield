/* ============================================
   SENTINELSHIELD — AGENT LOGS JS
   Terminal-Style AI Decision Log Viewer &
   Human-in-the-Loop Authorization
   ============================================ */

function classifyLog(text) {
    const t = (text || '').toLowerCase();
    if (t.includes('blocking') || t.includes('malicious') || t.includes('quarantin') || t.includes('drop')) return 'log-blocking';
    if (t.includes('detected') || t.includes('anomaly') || t.includes('classified') || t.includes('requires authorization')) return 'log-detected';
    if (t.includes('secured') || t.includes('success') || t.includes('neutralized') || t.includes('operational') || t.includes('approved')) return 'log-secured';
    if (t.includes('deploying') || t.includes('honeypot') || t.includes('probing') || t.includes('decoy')) return 'log-deploying';
    return 'log-monitoring';
}

function formatTimestamp(ts) {
    if (ts && ts.includes(' ')) {
        return ts.split(' ')[1];
    }
    return ts || new Date().toLocaleTimeString('en-US', { hour12: false });
}

async function approveAction(decisionId) {
    try {
        const btn = document.getElementById(`approve-btn-${decisionId}`);
        if (btn) {
            btn.disabled = true;
            btn.textContent = "Signing Ed25519...";
        }
        await SentinelAPI.approveDecision(decisionId);
        await loadPendingDecisions();
        await loadLogs();
    } catch (e) {
        alert("Failed to approve action: " + e.message);
    }
}

async function denyAction(decisionId) {
    try {
        const reason = prompt("Enter reason for denying security action:", "Operator policy override");
        if (reason === null) return;
        await SentinelAPI.denyDecision(decisionId, reason);
        await loadPendingDecisions();
        await loadLogs();
    } catch (e) {
        alert("Failed to deny action: " + e.message);
    }
}

async function loadPendingDecisions() {
    try {
        const container = document.getElementById("pendingDecisionsList");
        if (!container) return;

        const pending = await SentinelAPI.getDecisions('needs_approval');
        container.innerHTML = "";

        if (!pending || pending.length === 0) {
            container.innerHTML = `
                <div style="display:flex;align-items:center;gap:10px;color:#22c55e;font-size:13px;padding:6px 0">
                    <span style="font-size:18px">✓</span>
                    <span>All security actions resolved — No pending human approvals required</span>
                </div>
            `;
            return;
        }

        pending.forEach(d => {
            const item = document.createElement("div");
            item.className = "pending-decision-row";
            item.style.cssText = "display:flex;align-items:center;justify-content:space-between;padding:12px 14px;background:rgba(2,6,23,0.6);border:1px solid rgba(245,158,11,0.3);border-radius:8px;gap:16px;flex-wrap:wrap";

            item.innerHTML = `
                <div style="display:flex;flex-direction:column;gap:4px">
                    <div style="display:flex;align-items:center;gap:10px">
                        <span class="badge badge-tcp" style="background:rgba(245,158,11,0.15);color:#f59e0b;font-weight:700">${d.action.toUpperCase()}</span>
                        <code style="color:#e2e8f0;font-size:14px;font-weight:600">${d.target}</code>
                        <span style="font-size:12px;color:#ef4444;font-weight:600">Risk: ${d.risk_score}%</span>
                    </div>
                    <span style="font-size:12px;color:#94a3b8">${d.reason}</span>
                </div>
                <div style="display:flex;align-items:center;gap:10px">
                    <button id="approve-btn-${d.id}" onclick="approveAction(${d.id})" style="background:#22c55e;color:#020617;font-weight:700;font-size:12px;padding:6px 14px;border:none;border-radius:6px;cursor:pointer;transition:0.2s">✓ Approve & Enforce (Ed25519)</button>
                    <button onclick="denyAction(${d.id})" style="background:rgba(239,68,68,0.2);color:#ef4444;border:1px solid rgba(239,68,68,0.4);font-weight:600;font-size:12px;padding:6px 14px;border-radius:6px;cursor:pointer;transition:0.2s">✗ Deny</button>
                </div>
            `;
            container.appendChild(item);
        });
    } catch (e) {
        console.warn("Pending decisions error:", e.message);
    }
}

async function loadLogs() {
    try {
        const data = await SentinelAPI.getAgentLogs(40);
        if (!data) return;

        const list = document.getElementById("logList");
        if (!list) return;

        list.innerHTML = "";

        /* Log count */
        const countEl = document.getElementById("log-count");
        if (countEl) countEl.textContent = data.length;

        data.forEach((log, i) => {
            const item = document.createElement("li");
            const message = typeof log === 'string' ? log : log.message || log.decision || '';
            const ts = typeof log === 'string' ? formatTimestamp(null) : formatTimestamp(log.timestamp);
            const cls = classifyLog(message);

            const cmdBadge = (log.command_id && typeof log === 'object') ? 
                `<span style="color:#64748b;font-size:10px;margin-left:6px">[cmd:${log.command_id.substring(0,8)}]</span>` : '';

            item.innerHTML = `<span class="log-timestamp">[${ts}]</span><span class="${cls}">[Agent] ${message}</span>${cmdBadge}`;

            item.style.animationDelay = (i * 0.04) + 's';
            list.appendChild(item);
        });

        /* Auto-scroll to bottom */
        list.scrollTop = list.scrollHeight;

    } catch (error) {
        console.warn("Log loading error:", error.message);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    loadPendingDecisions();
    loadLogs();
    setInterval(loadPendingDecisions, 3000);
    setInterval(loadLogs, 2500);
});
