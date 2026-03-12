/* ============================================
   SENTINELSHIELD — AGENT LOGS JS
   Terminal-Style AI Decision Log Viewer
   ============================================ */

function classifyLog(text) {
    const t = text.toLowerCase();
    if (t.includes('blocking') || t.includes('malicious') || t.includes('quarantin')) return 'log-blocking';
    if (t.includes('detected') || t.includes('anomaly') || t.includes('classified')) return 'log-detected';
    if (t.includes('secured') || t.includes('success') || t.includes('neutralized') || t.includes('operational')) return 'log-secured';
    if (t.includes('deploying') || t.includes('honeypot') || t.includes('deployed')) return 'log-deploying';
    return 'log-monitoring';
}

function formatTimestamp(ts) {
    /* If timestamp from DB is full datetime, extract time portion */
    if (ts && ts.includes(' ')) {
        return ts.split(' ')[1];
    }
    return ts || new Date().toLocaleTimeString('en-US', { hour12: false });
}

async function loadLogs() {
    try {
        const res = await fetch("/api/logs");
        const data = await res.json();

        const list = document.getElementById("logList");
        list.innerHTML = "";

        /* Log count */
        const countEl = document.getElementById("log-count");
        if (countEl) countEl.textContent = data.length;

        data.forEach((log, i) => {
            const item = document.createElement("li");
            /* Support both old string format and new object format */
            const message = typeof log === 'string' ? log : log.message || log.decision || '';
            const ts = typeof log === 'string' ? formatTimestamp(null) : formatTimestamp(log.timestamp);
            const cls = classifyLog(message);

            item.innerHTML = `<span class="log-timestamp">[${ts}]</span><span class="${cls}">[Agent] ${message}</span>`;

            /* Staggered animation */
            item.style.animationDelay = (i * 0.08) + 's';

            list.appendChild(item);
        });

        /* Auto-scroll to bottom */
        list.scrollTop = list.scrollHeight;

    } catch (error) {
        console.error("Log loading error:", error);
    }
}

setInterval(loadLogs, 2000);
loadLogs();