/* ============================================
   SENTINELSHIELD — TRAFFIC MONITOR JS (Secured & Hardened)
   Real-Time Traffic Packet Stream with XSS Sanitization
   ============================================ */

function protocolBadge(proto) {
    const raw = (proto || 'TCP').toUpperCase();
    const clean = SentinelAPI.escapeHTML(raw);
    return `<span class="badge badge-${clean.toLowerCase()}">${clean}</span>`;
}

async function updateTraffic() {
    try {
        const data = await SentinelAPI.getTraffic(15);
        if (!data) return;

        /* Connection count */
        const countEl = document.getElementById("conn-count");
        if (countEl) countEl.textContent = data.length;

        /* Total bandwidth */
        const bwEl = document.getElementById("total-bw");
        if (bwEl) {
            const total = data.reduce((s, d) => s + (d.size || 0), 0);
            bwEl.textContent = total > 1000 ? (total / 1000).toFixed(1) + ' KB' : total + ' B';
        }

        /* Table */
        const table = document.getElementById("traffic-monitor");
        if (!table) return;

        if (data.length === 0) {
            table.innerHTML = '<tr><td colspan="5" style="text-align:center;color:#475569">No network packets in sliding window</td></tr>';
            return;
        }

        table.innerHTML = "";
        data.forEach(item => {
            const row = document.createElement('tr');
            const size = parseInt(item.size, 10) || 64;
            const timeSafe = SentinelAPI.escapeHTML(item.time);
            const srcSafe = SentinelAPI.escapeHTML(item.source);
            const dstSafe = SentinelAPI.escapeHTML(item.destination);

            row.innerHTML = `
                <td style="font-family:var(--font-mono);font-size:12px;color:#64748b">${timeSafe}</td>
                <td><code style="color:#e2e8f0">${srcSafe}</code></td>
                <td><code style="color:#e2e8f0">${dstSafe}</code></td>
                <td>${protocolBadge(item.protocol)}</td>
                <td>
                    <span style="font-variant-numeric:tabular-nums">${size} B</span>
                    <div style="margin-top:3px;height:3px;border-radius:2px;background:rgba(56,189,248,0.1);overflow:hidden">
                        <div style="height:100%;width:${Math.min(size / 15, 100)}%;background:rgba(56,189,248,0.5);border-radius:2px"></div>
                    </div>
                </td>
            `;
            table.appendChild(row);
        });

    } catch (error) {
        console.warn("Traffic update error:", error.message);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    updateTraffic();
    setInterval(updateTraffic, 2000);
});
