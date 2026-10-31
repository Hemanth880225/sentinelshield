/**
 * SentinelShield — Centralized Frontend API Client
 * Manages HTTP communication, authentication headers, error states,
 * loading states, and WebSocket real-time updates.
 */

(function (window) {
    'use strict';

    // Configuration
    const metaApiUrl = document.querySelector('meta[name="api-base-url"]')?.getAttribute('content');
    const API_BASE = window.SENTINEL_CONFIG?.API_BASE_URL || metaApiUrl || '/api';
    const WS_BASE = window.SENTINEL_CONFIG?.WS_BASE_URL || 
        (window.location.protocol === 'https:' ? 'wss://' : 'ws://') + (window.location.port === '5000' ? window.location.hostname + ':8000' : window.location.host) + '/ws';

    let apiKey = localStorage.getItem('sentinel_api_key') || 'sentinel-admin-sec-key-v2';
    let isBackendAvailable = true;
    let ws = null;
    let wsReconnectTimer = null;

    function getHeaders(customHeaders = {}) {
        return {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'X-API-Key': apiKey,
            ...customHeaders
        };
    }

    async function request(endpoint, options = {}) {
        const cleanEndpoint = endpoint.startsWith('/') ? endpoint.slice(1) : endpoint;
        const url = `${API_BASE}/${cleanEndpoint}`;

        const fetchOptions = {
            ...options,
            headers: getHeaders(options.headers)
        };

        try {
            const response = await fetch(url, fetchOptions);

            if (response.status === 401 || response.status === 403) {
                console.warn('SentinelShield: Authentication / Authorization required for', endpoint);
                window.dispatchEvent(new CustomEvent('sentinel:auth_error', { detail: { status: response.status } }));
            }

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({ detail: response.statusText }));
                throw new Error(errorData.detail || errorData.error || `HTTP error ${response.status}`);
            }

            // Connection healthy
            if (!isBackendAvailable) {
                isBackendAvailable = true;
                updateHealthIndicator(true);
                window.dispatchEvent(new CustomEvent('sentinel:connected'));
            }

            return await response.json();
        } catch (error) {
            console.error(`SentinelAPI Request Error [${endpoint}]:`, error);
            if (isBackendAvailable) {
                isBackendAvailable = false;
                updateHealthIndicator(false);
                window.dispatchEvent(new CustomEvent('sentinel:disconnected', { detail: { error } }));
            }
            throw error;
        }
    }

    function updateHealthIndicator(healthy) {
        const healthDot = document.querySelector('.health-dot');
        const healthText = document.querySelector('.system-health span:last-child');
        if (healthDot && healthText) {
            if (healthy) {
                healthDot.style.background = '#22c55e';
                healthDot.style.animation = 'healthPulse 2s infinite';
                healthText.textContent = 'System Healthy';
                healthText.style.color = '#22c55e';
            } else {
                healthDot.style.background = '#ef4444';
                healthDot.style.animation = 'none';
                healthText.textContent = 'Backend Reconnecting';
                healthText.style.color = '#ef4444';
            }
        }
    }

    // WebSocket Manager
    function initWebSocket(channel = 'dashboard', onMessage = null) {
        if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
            return;
        }

        const wsUrl = `${WS_BASE}/${channel}`;
        try {
            ws = new WebSocket(wsUrl);

            ws.onopen = function () {
                console.log(`[Sentinel WS] Connected to ${channel}`);
                if (wsReconnectTimer) clearTimeout(wsReconnectTimer);
            };

            ws.onmessage = function (event) {
                try {
                    const data = JSON.parse(event.data);
                    if (onMessage) onMessage(data);
                    window.dispatchEvent(new CustomEvent(`sentinel:ws:${channel}`, { detail: data }));
                } catch (e) {
                    console.error('[Sentinel WS] Error parsing message:', e);
                }
            };

            ws.onerror = function (err) {
                console.warn('[Sentinel WS] Error:', err);
            };

            ws.onclose = function () {
                console.log('[Sentinel WS] Disconnected. Reconnecting in 5s...');
                ws = null;
                wsReconnectTimer = setTimeout(() => initWebSocket(channel, onMessage), 5000);
            };
        } catch (e) {
            console.warn('[Sentinel WS] WebSocket initialization failed, falling back to HTTP polling:', e);
        }
    }

    // Public API
    window.SentinelAPI = {
        get: (endpoint) => request(endpoint, { method: 'GET' }),
        post: (endpoint, body) => request(endpoint, { method: 'POST', body: JSON.stringify(body) }),
        put: (endpoint, body) => request(endpoint, { method: 'PUT', body: JSON.stringify(body) }),
        delete: (endpoint) => request(endpoint, { method: 'DELETE' }),

        // High-level Domain Methods
        getStatus: () => request('status'),
        getTraffic: (limit = 15) => request(`traffic?limit=${limit}`),
        getThreats: () => request('threats'),
        getThreatsSummary: () => request('threats/summary'),
        getHoneypots: () => request('honeypots'),
        getAgentLogs: (limit = 40) => request(`logs?limit=${limit}`),
        getDecisions: (status = null) => request(status ? `decisions?status=${status}` : 'decisions'),
        approveDecision: (id) => request(`decisions/${id}/approve`, { method: 'POST' }),
        denyDecision: (id, reason = 'Admin override') => request(`decisions/${id}/deny`, { method: 'POST', body: JSON.stringify({ reason }) }),
        interactHoneypot: (code, ip, payload = '') => request('honeypots/interact', { method: 'POST', body: JSON.stringify({ honeypot_code: code, attacker_ip: ip, payload }) }),
        deployHoneypot: (service, port) => request('honeypots/deploy', { method: 'POST', body: JSON.stringify({ service, port }) }),
        getRules: () => request('enforcement/rules'),
        getAudit: () => request('enforcement/audit'),
        getPolicy: () => request('policy'),
        updatePolicy: (policy) => request('policy', { method: 'PUT', body: JSON.stringify(policy) }),

        // Utilities
        setApiKey: (key) => {
            apiKey = key;
            localStorage.setItem('sentinel_api_key', key);
        },
        initWebSocket,
        isAvailable: () => isBackendAvailable
    };

})(window);
