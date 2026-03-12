/* ============================================
   SENTINELSHIELD — THREATS JS
   Threat Intelligence Logic with Chart
   ============================================ */

let threatBarChart = null;

function initThreatChart() {
    const ctx = document.getElementById('threatBarChart');
    if (!ctx) return;

    threatBarChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['Port Scan', 'Brute Force', 'Malware Attempt', 'Suspicious Login'],
            datasets: [{
                label: 'Occurrences',
                data: [0, 0, 0, 0],
                backgroundColor: [
                    'rgba(56,189,248,0.6)',
                    'rgba(245,158,11,0.6)',
                    'rgba(239,68,68,0.6)',
                    'rgba(139,92,246,0.6)'
                ],
                borderColor: [
                    'rgba(56,189,248,0.9)',
                    'rgba(245,158,11,0.9)',
                    'rgba(239,68,68,0.9)',
                    'rgba(139,92,246,0.9)'
                ],
                borderWidth: 1,
                borderRadius: 6,
                barPercentage: 0.6
            }]
        },
        options: {
            responsive: true,
            scales: {
                x: {
                    ticks: { color: '#64748b', font: { size: 11 } },
                    grid: { display: false }
                },
                y: {
                    ticks: { color: '#475569', font: { size: 10 }, stepSize: 1 },
                    grid: { color: 'rgba(30,41,59,0.3)' },
                    beginAtZero: true
                }
            },
            plugins: {
                legend: { display: false }
            }
        }
    });
}

function severityBadge(sev) {
    const s = sev.toLowerCase();
    return `<span class="severity severity-${s}"><span class="severity-dot"></span>${sev}</span>`;
}

async function loadThreats() {
    try {
        const res = await fetch("/api/threats");
        const data = await res.json();

        /* Summary cards */
        document.getElementById("threat-total").textContent = data.length;

        let high = 0, med = 0, low = 0;
        const typeCounts = { 'Port Scan': 0, 'Brute Force': 0, 'Malware Attempt': 0, 'Suspicious Login': 0 };

        data.forEach(t => {
            if (t.severity === 'High') high++;
            else if (t.severity === 'Medium') med++;
            else low++;
            if (typeCounts[t.type] !== undefined) typeCounts[t.type]++;
        });

        document.getElementById("threat-high").textContent = high;
        document.getElementById("threat-medium").textContent = med;
        document.getElementById("threat-low").textContent = low;

        /* Chart */
        if (threatBarChart) {
            threatBarChart.data.datasets[0].data = [
                typeCounts['Port Scan'],
                typeCounts['Brute Force'],
                typeCounts['Malware Attempt'],
                typeCounts['Suspicious Login']
            ];
            threatBarChart.update('none');
        }

        /* Table */
        const table = document.querySelector("#threatTable tbody");
        table.innerHTML = "";

        data.forEach(threat => {
            const row = document.createElement("tr");
            if (threat.severity === 'High') row.classList.add('glow-alert');

            row.innerHTML = `
                <td style="font-family:var(--font-mono);font-size:12px;color:#64748b">${threat.time}</td>
                <td><code style="color:#e2e8f0">${threat.ip}</code></td>
                <td style="font-weight:500">${threat.type}</td>
                <td>${threat.target}</td>
                <td>${severityBadge(threat.severity)}</td>
            `;

            table.appendChild(row);
        });

    } catch (error) {
        console.error("Threat loading error:", error);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    initThreatChart();
    loadThreats();
    setInterval(loadThreats, 2000);
});