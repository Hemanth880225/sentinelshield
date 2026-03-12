/* ============================================
   SENTINELSHIELD — HONEYPOTS JS
   Deception System Monitor
   ============================================ */

function statusBadge(status) {
    const s = status.toLowerCase();
    const cls = s === 'active' ? 'status-active' : 'status-triggered';
    return `<span class="status-badge ${cls}"><span class="status-dot"></span>${status}</span>`;
}

function serviceIcon(service) {
    const icons = {
        'Fake SSH': '🔑',
        'Fake FTP': '📁',
        'Fake Telnet': '🖥️'
    };
    return icons[service] || '🎭';
}

async function loadHoneypots() {
    try {
        const res = await fetch("/api/honeypots");
        const data = await res.json();

        /* Summary counters */
        document.getElementById("hp-total").textContent = data.length;
        let active = 0, triggered = 0;
        data.forEach(h => {
            if (h.status === 'Active') active++;
            else triggered++;
        });
        document.getElementById("hp-active").textContent = active;
        document.getElementById("hp-triggered").textContent = triggered;

        /* Card Grid */
        const grid = document.getElementById("honeypotGrid");
        grid.innerHTML = "";

        data.forEach(h => {
            const card = document.createElement('div');
            card.className = 'honeypot-card';
            if (h.status === 'Triggered') card.style.borderColor = 'rgba(239,68,68,0.3)';

            card.innerHTML = `
                <div class="honeypot-card-header">
                    <span class="honeypot-id">${h.id}</span>
                    ${statusBadge(h.status)}
                </div>
                <div class="honeypot-meta">
                    <div class="honeypot-meta-item">
                        <span class="honeypot-meta-label">Service</span>
                        <span class="honeypot-meta-value">${serviceIcon(h.service)} ${h.service}</span>
                    </div>
                    <div class="honeypot-meta-item">
                        <span class="honeypot-meta-label">Interactions</span>
                        <span class="honeypot-meta-value" style="color:#38bdf8">${h.interactions}</span>
                    </div>
                    <div class="honeypot-meta-item">
                        <span class="honeypot-meta-label">Last Trigger</span>
                        <span class="honeypot-meta-value" style="font-family:var(--font-mono);font-size:11px">${h.last_trigger}</span>
                    </div>
                    <div class="honeypot-meta-item">
                        <span class="honeypot-meta-label">Activity</span>
                        <div style="margin-top:4px;height:4px;border-radius:2px;background:rgba(56,189,248,0.1);overflow:hidden">
                            <div style="height:100%;width:${Math.min(h.interactions * 5, 100)}%;background:${h.status === 'Triggered' ? 'rgba(239,68,68,0.6)' : 'rgba(56,189,248,0.5)'};border-radius:2px;transition:width 0.5s"></div>
                        </div>
                    </div>
                </div>
            `;

            grid.appendChild(card);
        });

        /* Table */
        const table = document.querySelector("#honeypotTable tbody");
        table.innerHTML = "";

        data.forEach(h => {
            const row = document.createElement("tr");
            row.innerHTML = `
                <td style="font-family:var(--font-mono);font-weight:700;color:#38bdf8">${h.id}</td>
                <td>${serviceIcon(h.service)} ${h.service}</td>
                <td>${statusBadge(h.status)}</td>
                <td style="font-variant-numeric:tabular-nums;font-weight:600">${h.interactions}</td>
                <td style="font-family:var(--font-mono);font-size:12px;color:#64748b">${h.last_trigger}</td>
            `;
            table.appendChild(row);
        });

    } catch (error) {
        console.error("Honeypot loading error:", error);
    }
}

setInterval(loadHoneypots, 2000);
loadHoneypots();