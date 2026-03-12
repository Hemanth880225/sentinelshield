/* ============================================
   SENTINELSHIELD — TRAFFIC MONITOR JS
   ============================================ */

function protocolBadge(proto) {
    const p = proto.toUpperCase();
    return `<span class="badge badge-${p.toLowerCase()}">${p}</span>`;
}

async function updateTraffic() {
    try {
        const response = await fetch("/api/traffic");
        const data = await response.json();

        /* Connection count */
        const countEl = document.getElementById("conn-count");
        if (countEl) countEl.textContent = data.length;

        /* Total bandwidth */
        const bwEl = document.getElementById("total-bw");
        if (bwEl) {
            const total = data.reduce((s, d) => s + d.size, 0);
            bwEl.textContent = total > 1000 ? (total / 1000).toFixed(1) + ' KB' : total + ' B';
        }

        /* Table */
        const table = document.getElementById("traffic-monitor");
        table.innerHTML = "";

        data.forEach(item => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td style="font-family:var(--font-mono);font-size:12px;color:#64748b">${item.time}</td>
                <td><code style="color:#e2e8f0">${item.source}</code></td>
                <td><code style="color:#e2e8f0">${item.destination}</code></td>
                <td>${protocolBadge(item.protocol)}</td>
                <td>
                    <span style="font-variant-numeric:tabular-nums">${item.size} B</span>
                    <div style="margin-top:3px;height:3px;border-radius:2px;background:rgba(56,189,248,0.1);overflow:hidden">
                        <div style="height:100%;width:${Math.min(item.size / 15, 100)}%;background:rgba(56,189,248,0.5);border-radius:2px"></div>
                    </div>
                </td>
            `;
            table.appendChild(row);
        });

    } catch (error) {
        console.error("Traffic update failed:", error);
    }
}

setInterval(updateTraffic, 2000);
updateTraffic();