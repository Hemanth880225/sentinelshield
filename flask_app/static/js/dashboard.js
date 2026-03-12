/* ============================================
   SENTINELSHIELD — DASHBOARD JS
   SOC Dashboard Logic with Charts & Counters
   ============================================ */

/* ---- Animated Counter ---- */
function animateCounter(el, target) {
    const current = parseInt(el.textContent) || 0;
    if (current === target) return;

    const duration = 600;
    const start = performance.now();
    const startVal = current === '--' ? 0 : current;

    function step(timestamp) {
        const progress = Math.min((timestamp - start) / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3);
        el.textContent = Math.round(startVal + (target - startVal) * eased);
        if (progress < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
}


/* ---- Protocol Badge Helper ---- */
function protocolBadge(proto) {
    const p = proto.toUpperCase();
    return `<span class="badge badge-${p.toLowerCase()}">${p}</span>`;
}


/* ---- Charts Setup ---- */
let threatDonutChart = null;
let trafficLineChart = null;
const trafficHistory = [];
const MAX_HISTORY = 20;

function initCharts() {
    /* Threat Distribution Donut */
    const donutCtx = document.getElementById('threatDonut');
    if (donutCtx) {
        threatDonutChart = new Chart(donutCtx, {
            type: 'doughnut',
            data: {
                labels: ['Port Scan', 'Brute Force', 'Malware', 'Suspicious Login'],
                datasets: [{
                    data: [0, 0, 0, 0],
                    backgroundColor: [
                        'rgba(56,189,248,0.8)',
                        'rgba(245,158,11,0.8)',
                        'rgba(239,68,68,0.8)',
                        'rgba(139,92,246,0.8)'
                    ],
                    borderColor: '#0f172a',
                    borderWidth: 2,
                    hoverOffset: 6
                }]
            },
            options: {
                responsive: true,
                cutout: '65%',
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: '#94a3b8',
                            font: { family: 'Inter', size: 11 },
                            padding: 16,
                            usePointStyle: true,
                            pointStyleWidth: 8
                        }
                    }
                }
            }
        });
    }

    /* Traffic Volume Line */
    const lineCtx = document.getElementById('trafficLine');
    if (lineCtx) {
        trafficLineChart = new Chart(lineCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Packets',
                    data: [],
                    borderColor: '#38bdf8',
                    backgroundColor: 'rgba(56,189,248,0.08)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    pointRadius: 0,
                    pointHoverRadius: 4,
                    pointHoverBackgroundColor: '#38bdf8'
                }]
            },
            options: {
                responsive: true,
                scales: {
                    x: {
                        ticks: { color: '#475569', font: { size: 10 } },
                        grid: { color: 'rgba(30,41,59,0.4)' }
                    },
                    y: {
                        ticks: { color: '#475569', font: { size: 10 } },
                        grid: { color: 'rgba(30,41,59,0.3)' },
                        beginAtZero: true
                    }
                },
                plugins: {
                    legend: { display: false }
                },
                interaction: {
                    intersect: false,
                    mode: 'index'
                }
            }
        });
    }
}


/* ---- Update Dashboard ---- */
async function updateDashboard() {
    try {
        /* Status */
        const statusRes = await fetch("/api/status");
        const status = await statusRes.json();

        animateCounter(document.getElementById("devices_online"), status.devices_online);
        animateCounter(document.getElementById("threats_detected"), status.threats_detected);
        animateCounter(document.getElementById("honeypots_active"), status.honeypots_active);

        const netEl = document.getElementById("network_status");
        netEl.textContent = status.network_status;
        netEl.style.color = status.network_status === 'Secure' ? '#22c55e' : '#ef4444';

        /* Traffic */
        const trafficRes = await fetch("/api/traffic");
        const traffic = await trafficRes.json();

        const table = document.getElementById("traffic-body");
        table.innerHTML = "";

        traffic.forEach(item => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td style="font-family:'JetBrains Mono',monospace;font-size:12px;color:#64748b">${item.time}</td>
                <td><code style="color:#e2e8f0">${item.source}</code></td>
                <td><code style="color:#e2e8f0">${item.destination}</code></td>
                <td>${protocolBadge(item.protocol)}</td>
                <td style="font-variant-numeric:tabular-nums">${item.size} B</td>
            `;
            table.appendChild(row);
        });

        /* Update traffic volume chart */
        if (trafficLineChart) {
            const now = new Date();
            const timeLabel = now.toLocaleTimeString('en-US', { hour12: false });
            const totalSize = traffic.reduce((sum, t) => sum + t.size, 0);

            trafficHistory.push({ time: timeLabel, value: totalSize });
            if (trafficHistory.length > MAX_HISTORY) trafficHistory.shift();

            trafficLineChart.data.labels = trafficHistory.map(h => h.time);
            trafficLineChart.data.datasets[0].data = trafficHistory.map(h => h.value);
            trafficLineChart.update('none');
        }

        /* Update threat donut with actual data from /threats */
        const threatRes = await fetch("/api/threats");
        const threats = await threatRes.json();

        if (threatDonutChart) {
            const counts = { 'Port Scan': 0, 'Brute Force': 0, 'Malware Attempt': 0, 'Suspicious Login': 0 };
            threats.forEach(t => { if (counts[t.type] !== undefined) counts[t.type]++; });

            threatDonutChart.data.datasets[0].data = [
                counts['Port Scan'],
                counts['Brute Force'],
                counts['Malware Attempt'],
                counts['Suspicious Login']
            ];
            threatDonutChart.update('none');
        }

    } catch (error) {
        console.error("Dashboard update error:", error);
    }
}


/* ---- Initialize ---- */
document.addEventListener('DOMContentLoaded', () => {
    initCharts();
    updateDashboard();
    setInterval(updateDashboard, 3000);
});