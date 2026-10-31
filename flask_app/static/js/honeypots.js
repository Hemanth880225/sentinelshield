/* ============================================
   SENTINELSHIELD — HONEYPOTS JS (Secured & Hardened)
   Deception System Monitor & Interactive Decoys
   ============================================ */

function statusBadge(status) {
    const raw = (status || 'Active');
    const safeStatus = SentinelAPI.escapeHTML(raw);
    const s = safeStatus.toLowerCase();
    const cls = s === 'active' ? 'status-active' : 'status-triggered';
    return `<span class="status-badge ${cls}"><span class="status-dot"></span>${safeStatus}</span>`;
}

function serviceIcon(service) {
    const icons = {
        'Fake SSH': '🔑',
        'Fake FTP': '📁',
        'Fake Telnet': '🖥️',
        'Fake HTTP': '🌐',
        'Fake SMTP': '✉️'
    };
    return icons[service] || '🎭';
}

async function triggerProbe(honeypotId) {
    try {
        const attackerIps = ["45.33.32.8", "185.220.101.5", "89.248.165.12", "194.26.29.41"];
        const randomAttacker = attackerIps[Math.floor(Math.random() * attackerIps.length)];
        
        await SentinelAPI.interactHoneypot(honeypotId, randomAttacker, "PROBE_SIMULATED");
        await loadHoneypots();
    } catch (e) {
        console.error("Failed to trigger probe:", e);
    }
}

async function loadHoneypots() {
    try {
        const data = await SentinelAPI.getHoneypots();
        if (!data) return;

        /* Summary counters */
        const totalEl = document.getElementById("hp-total");
        if (totalEl) totalEl.textContent = data.length;

        let active = 0, triggered = 0;
        data.forEach(h => {
            if (h.status === 'Active') active++;
            else triggered++;
        });

        const activeEl = document.getElementById("hp-active");
        const trigEl = document.getElementById("hp-triggered");
        if (activeEl) activeEl.textContent = active;
        if (trigEl) trigEl.textContent = triggered;

        /* Card Grid */
        const grid = document.getElementById("honeypotGrid");
        if (!grid) return;

        grid.innerHTML = "";

        data.forEach(h => {
            const card = document.createElement('div');
            card.className = 'honeypot-card';
            if (h.status === 'Triggered') card.style.borderColor = 'rgba(239,68,68,0.3)';

            const idSafe = SentinelAPI.escapeHTML(h.id);
            const servSafe = SentinelAPI.escapeHTML(h.service);
            const trigSafe = SentinelAPI.escapeHTML(h.last_trigger);
            const interactionsNum = parseInt(h.interactions, 10) || 0;

            card.innerHTML = `
                <div class="honeypot-card-header">
                    <span class="honeypot-id">${idSafe}</span>
                    <div style="display:flex;align-items:center;gap:8px">
                        ${statusBadge(h.status)}
                        <button class="btn-probe" data-id="${idSafe}" title="Simulate attacker interaction probe" style="background:rgba(139,92,246,0.15);border:1px solid rgba(139,92,246,0.4);color:#c084fc;border-radius:6px;padding:3px 8px;font-size:11px;cursor:pointer">Probe</button>
                    </div>
                </div>
                <div class="honeypot-meta">
                    <div class="honeypot-meta-item">
                        <span class="honeypot-meta-label">Service</span>
                        <span class="honeypot-meta-value">${serviceIcon(h.service)} ${servSafe}</span>
                    </div>
                    <div class="honeypot-meta-item">
                        <span class="honeypot-meta-label">Interactions</span>
                        <span class="honeypot-meta-value" style="color:#38bdf8">${interactionsNum}</span>
                    </div>
                    <div class="honeypot-meta-item">
                        <span class="honeypot-meta-label">Last Trigger</span>
                        <span class="honeypot-meta-value" style="font-family:var(--font-mono);font-size:11px">${trigSafe}</span>
                    </div>
                    <div class="honeypot-meta-item">
                        <span class="honeypot-meta-label">Activity</span>
                        <div style="margin-top:4px;height:4px;border-radius:2px;background:rgba(56,189,248,0.1);overflow:hidden">
                            <div style="height:100%;width:${Math.min(interactionsNum * 5, 100)}%;background:${h.status === 'Triggered' ? 'rgba(239,68,68,0.6)' : 'rgba(56,189,248,0.5)'};border-radius:2px;transition:width 0.5s"></div>
                        </div>
                    </div>
                </div>
            `;

            const probeBtn = card.querySelector('.btn-probe');
            if (probeBtn) {
                probeBtn.addEventListener('click', () => triggerProbe(h.id));
            }

            grid.appendChild(card);
        });

        /* Table */
        const table = document.querySelector("#honeypotTable tbody");
        if (!table) return;

        table.innerHTML = "";
        data.forEach(h => {
            const row = document.createElement("tr");
            const idSafe = SentinelAPI.escapeHTML(h.id);
            const servSafe = SentinelAPI.escapeHTML(h.service);
            const trigSafe = SentinelAPI.escapeHTML(h.last_trigger);
            const interactionsNum = parseInt(h.interactions, 10) || 0;

            row.innerHTML = `
                <td style="font-family:var(--font-mono);font-weight:700;color:#38bdf8">${idSafe}</td>
                <td>${serviceIcon(h.service)} ${servSafe}</td>
                <td>${statusBadge(h.status)}</td>
                <td style="font-variant-numeric:tabular-nums;font-weight:600">${interactionsNum}</td>
                <td style="font-family:var(--font-mono);font-size:12px;color:#64748b">${trigSafe}</td>
            `;
            table.appendChild(row);
        });

    } catch (error) {
        console.warn("Honeypot loading warning:", error.message);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    loadHoneypots();
    setInterval(loadHoneypots, 2500);
});
