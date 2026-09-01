document.addEventListener('DOMContentLoaded', () => {
    // ── DOM References ────────────────────────────────────────
    const loginContainer    = document.getElementById('login-container');
    const dashboardContainer = document.getElementById('dashboard-container');
    const loginForm         = document.getElementById('login-form');
    const loginBtn          = document.getElementById('login-btn');
    const loginError        = document.getElementById('login-error');
    const logoutBtn         = document.getElementById('logout-btn');

    // ── State ─────────────────────────────────────────────────
    var tableUpdatePending  = false;
    var ppsIntervalId       = null;
    
    let token              = sessionStorage.getItem('ids_access_token');
    let threatChartInstance = null;
    let wsConnection        = null;
    let threatMap           = null;
    let wsLogs              = [];          // rolling buffer of last 50 packets
    let allLogs             = [];          // full log list for filtering
    let alertCount          = 0;
    let totalPackets        = 0;
    let totalAnomalies      = 0;
    let ppsCounter          = 0;          // packets this second
    let ppsHistory          = new Array(30).fill(0); // rolling PPS values
    let ppsLabels           = new Array(30).fill('').map(() => new Date().toLocaleTimeString()); // time labels for PPS
    window._threatHistory   = new Array(30).fill(0); // rolling threat values
    let geoCache            = {};         // IP → {country, org, city, lat, lon}
    let pendingLookups      = new Set();  // IPs currently being fetched
    let currentSearchTerm   = '';

    const API_BASE = 'http://localhost:8000';
    const WS_BASE  = 'ws://localhost:8000';

    console.log('[IDS] Script loaded, state initialized.');


    // ── PPS ticker — count packets per second ─────────────────
    function startPPSTicker() {
        if (ppsIntervalId) clearInterval(ppsIntervalId);
        ppsIntervalId = setInterval(() => {
            try {
                const now = new Date().toLocaleTimeString();
                
                // Push values to history
                ppsHistory.push(ppsCounter);
                ppsLabels.push(now);
                
                // Maintain threat history
                const recentPackets = allLogs.slice(0, Math.max(1, ppsCounter));
                const maxRecentThreat = recentPackets.length > 0 
                    ? Math.max(...recentPackets.map(p => p.threat_level || 0))
                    : (wsLogs.length > 0 ? wsLogs[wsLogs.length-1].threat_level : 0);
                    
                window._threatHistory.push(maxRecentThreat);

                while (ppsHistory.length > 30) {
                    ppsHistory.shift();
                    ppsLabels.shift();
                    window._threatHistory.shift();
                }

                const ppsDisplay = document.getElementById('stat-pps');
                if (ppsDisplay) ppsDisplay.textContent = ppsCounter;
                
                ppsCounter = 0;
                updateChart();
            } catch (err) {
                console.error('[IDS] Ticker Error:', err);
            }
        }, 1000);
    }

    // ── Authentication ────────────────────────────────────────
    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value;
        const btn = document.getElementById('login-btn');

        btn.textContent = 'Authenticating…';
        btn.disabled = true;

        try {
            // LOGIN
            const params = new URLSearchParams();
            params.append('username', username);
            params.append('password', password);

            const res = await fetch(`${API_BASE}/token`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: params
            });

            if (!res.ok) throw new Error('Invalid credentials. Please try again.');

            const data = await res.json();
            token = data.access_token;
            sessionStorage.setItem('ids_access_token', token);
            sessionStorage.setItem('ids_user_role', data.role || 'Analyst');
            loginError.classList.add('hidden');
            
            // Role-based redirection
            if (data.role === 'HeadAdmin') {
                window.location.href = 'head_admin_dashboard.html';
            } else if (data.role === 'Admin') {
                window.location.href = 'admin_dashboard.html';
            } else if (data.role === 'Analyst') {
                window.location.href = 'analyst_dashboard.html';
            } else {
                showDashboard();
            }
        } catch (err) {
            loginError.textContent = err.message;
            loginError.classList.remove('hidden');
        } finally {
            btn.textContent = 'Authenticate →';
            btn.disabled = false;
        }
    });

    logoutBtn.addEventListener('click', () => {
        token = null;
        sessionStorage.removeItem('ids_access_token');
        sessionStorage.removeItem('ids_user_role');
        if (wsConnection) { wsConnection.close(); wsConnection = null; }
        loginContainer.classList.remove('hidden');
        dashboardContainer.classList.add('hidden');
        loginForm.reset();
        wsLogs = []; allLogs = []; alertCount = 0; totalPackets = 0; totalAnomalies = 0;
        ppsCounter = 0;
        ppsHistory = new Array(30).fill(0);
        ppsLabels = new Array(30).fill('').map(() => new Date().toLocaleTimeString());
        window._threatHistory = new Array(30).fill(0);
    });

    // ── Dashboard bootstrap ───────────────────────────────────
    function showDashboard() {
        console.log('[IDS] Initializing dashboard components...');
        loginContainer.classList.add('hidden');
        dashboardContainer.classList.remove('hidden');
        
        try { initChart(); } catch(e) { console.error('[IDS] Chart init failed:', e); }
        try { initMap(); } catch(e) { console.error('[IDS] Map init failed:', e); }
        
        // Ensure map is sized correctly if it was hidden
        setTimeout(() => { if(threatMap) threatMap.invalidateSize(); }, 500);

        connectWebSocket();
        startPPSTicker();
        window.trackConnectedDevices();
    }

    // ── Chart.js — dual dataset: Threat Level + PPS ───────────
    function initChart() {
        const ctx = document.getElementById('threatChart').getContext('2d');
        if (threatChartInstance) threatChartInstance.destroy();

        threatChartInstance = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    {
                        label: 'Anomaly Threat Level',
                        data: [],
                        borderColor: 'rgba(255, 71, 87, 0.9)',
                        backgroundColor: 'rgba(255, 71, 87, 0.08)',
                        borderWidth: 2,
                        fill: true,
                        tension: 0.4,
                        pointRadius: 2,
                        yAxisID: 'yThreat',
                    },
                    {
                        label: 'Packets / Second',
                        data: [],
                        borderColor: 'rgba(0, 212, 255, 0.9)',
                        backgroundColor: 'rgba(0, 212, 255, 0.06)',
                        borderWidth: 2,
                        fill: true,
                        tension: 0.4,
                        pointRadius: 2,
                        yAxisID: 'yPPS',
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: { duration: 0 }, // Set to 0 for smoother real-time updates
                interaction: { mode: 'index', intersect: false },
                plugins: {
                    legend: {
                        labels: { color: '#9CA3AF', boxWidth: 12, font: { size: 11 } }
                    },
                    tooltip: {
                        backgroundColor: 'rgba(10,14,28,0.95)',
                        borderColor: 'rgba(0,212,255,0.3)',
                        borderWidth: 1,
                        titleColor: '#e8eaf0',
                        bodyColor: '#9CA3AF',
                    }
                },
                scales: {
                    x: {
                        ticks: { color: '#6b7a99', maxTicksLimit: 8, font: { size: 10 } },
                        grid: { color: 'rgba(255,255,255,0.04)' }
                    },
                    yThreat: {
                        position: 'left',
                        min: 0, max: 1,
                        ticks: { color: 'rgba(255,71,87,0.8)', font: { size: 10 } },
                        grid: { color: 'rgba(255,255,255,0.04)' },
                        title: { display: true, text: 'Threat', color: 'rgba(255,71,87,0.6)', font: { size: 10 } }
                    },
                    yPPS: {
                        position: 'right',
                        min: 0,
                        suggestedMax: 10, // Gives some initial headroom
                        ticks: { color: 'rgba(0,212,255,0.8)', font: { size: 10 } },
                        grid: { drawOnChartArea: false },
                        title: { display: true, text: 'PPS', color: 'rgba(0,212,255,0.6)', font: { size: 10 } }
                    }
                }
            }
        });
    }

    function updateChart() {
        if (!threatChartInstance) return;
        
        // Sync labels and data points
        threatChartInstance.data.labels = ppsLabels;
        threatChartInstance.data.datasets[0].data = window._threatHistory;
        threatChartInstance.data.datasets[1].data = ppsHistory;
        
        // If it's the first few updates, do a full update to ensure scales are right
        if (totalPackets < 5) {
            threatChartInstance.update();
        } else {
            threatChartInstance.update('none');
        }
    }

    function initMap() {
        if (threatMap) return;
        threatMap = L.map('threat-map', {
            minZoom: 1.5,
            maxZoom: 19
        }).setView([20, 0], 2);

        // Google Roadmap (Clean Vector with countries, states, and cities) Layer
        L.tileLayer('https://mt1.google.com/vt/lyrs=m&x={x}&y={y}&z={z}', {
            maxZoom: 19,
            className: 'map-tiles-dark',
            attribution: '&copy; Google Maps'
        }).addTo(threatMap);
    }

    async function fetchGeoIP(ip) {
        if (!token) return null;
        if (geoCache[ip]) return geoCache[ip];
        if (pendingLookups.has(ip)) return null;
        pendingLookups.add(ip);
        
        try {
            console.log(`[IDS] Fetching Geo-IP for ${ip}...`);
            const res = await fetch(`${API_BASE}/geo-ip/${ip}`);
            if (res.ok) {
                const geo = await res.json();
                geoCache[ip] = geo;
                console.log(`[IDS] Geo-IP success: ${ip} -> ${geo.country}`);
                
                // Re-render table if a lookup finishes
                if (!tableUpdatePending) {
                    tableUpdatePending = true;
                    requestAnimationFrame(() => {
                        try { renderLogsTable(currentSearchTerm); } finally { tableUpdatePending = false; }
                    });
                }
                return geo;
            }
        } catch (e) { 
            console.error(`[IDS] Geo-IP error for ${ip}:`, e);
        } finally {
            pendingLookups.delete(ip);
        }
        return null;
    }

    async function addMapMarker(ip, reasons, type) {
        if (!token || !threatMap) return;

        let geo = geoCache[ip];
        if (!geo && !pendingLookups.has(ip)) {
            geo = await fetchGeoIP(ip);
        }

        if (!geo || (geo.lat === 0 && geo.lon === 0)) return;

        const isAnomaly = type === 'Anomaly';
        
        // Different icons for Normal vs Anomaly
        const markerIcon = L.divIcon({
            className: 'map-marker',
            html: isAnomaly 
                ? `<div class="pulse-dot-red" style="
                    width:14px; height:14px;
                    background:#ff4757;
                    border: 2px solid white;
                    border-radius:50%;
                    box-shadow: 0 0 15px rgba(255,71,87,0.8);
                "></div>`
                : `<div class="traffic-dot-cyan" style="
                    width:8px; height:8px;
                    background:#00d4ff;
                    border: 1px solid white;
                    border-radius:50%;
                "></div>`,
            iconSize: isAnomaly ? [14, 14] : [8, 8],
            iconAnchor: isAnomaly ? [7, 7] : [4, 4]
        });

        const reasonHtml = reasons && reasons.length
            ? `<br><span style="color:#ff4757;font-size:11px">${reasons.join(', ')}</span>`
            : '';

        const marker = L.marker([geo.lat, geo.lon], { icon: markerIcon })
            .addTo(threatMap)
            .bindPopup(`
                <b style="color:${isAnomaly ? '#ff4757' : '#00d4ff'}">${isAnomaly ? 'Anomaly' : 'Traffic'}: ${ip}</b><br>
                <span style="color:#9CA3AF">${geo.country}${geo.city ? ', ' + geo.city : ''}</span><br>
                <span style="color:#6b7a99;font-size:11px">${geo.org}</span>
                ${reasonHtml}
            `);

        // If it's an anomaly, pan the map to it
        if (isAnomaly) {
            threatMap.panTo([geo.lat, geo.lon]);
        }

        // Remove old markers after 30 seconds to keep map clean
        setTimeout(() => {
            threatMap.removeLayer(marker);
        }, isAnomaly ? 60000 : 30000);
    }

    // ── Network Device Scanner ────────────────────────────────
    window.trackConnectedDevices = async function () {
        if (!token) return;
        const deviceList = document.getElementById('device-list');
        if (!deviceList) return;
        deviceList.innerHTML = '<li class="status-msg">Scanning network range (ARP &amp; Ping discovery)…</li>';

        try {
            const response = await fetch(`${API_BASE}/api/scan-network`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            const data = await response.json();
            deviceList.innerHTML = '';

            if (!data.connected_devices || data.connected_devices.length === 0) {
                deviceList.innerHTML = '<li>No devices detected on LAN.</li>';
                return;
            }

            data.connected_devices.forEach(device => {
                const item = document.createElement('li');
                const isHost = device.is_host || (device.name && device.name.includes('(This PC)'));
                const hostBadge = isHost 
                    ? ` <span class="px-2 py-0.5 text-xs bg-cyan-500/20 text-cyan-300 font-bold rounded border border-cyan-500/30 uppercase tracking-wider ml-1">THIS PC</span>`
                    : '';
                const cleanName = device.name ? device.name.replace(/\s*\(This PC\)/i, '') : '';
                const nameDisplay = cleanName && cleanName !== 'Unknown Device' 
                    ? ` — <span class="text-cyan-400 font-semibold">${escapeHTML(cleanName)}</span>` 
                    : '';
                item.innerHTML = `<strong>${device.ip}</strong>${nameDisplay}${hostBadge} &nbsp;|&nbsp; MAC: <span>${device.mac}</span>`;
                deviceList.appendChild(item);
            });
        } catch (err) {
            console.error('[Network Scan Error]', err);
            deviceList.innerHTML = '<li style="color:#ff4757">ARP scan failed — check backend &amp; admin rights.</li>';
        }
    };
    // Removed periodic scanning interval as per user request to only scan on manual click after load.
    // setInterval(window.trackConnectedDevices, 30000);

    // ── System Status Helper ──────────────────────────────────
    function updateSystemStatus(state) {
        const statusBadge = document.getElementById('system-status');
        if (!statusBadge) return;
        
        if (state === 'connected') {
            statusBadge.className = "flex items-center text-green-400 font-semibold bg-green-500/10 border border-green-500/20 px-3 py-1.5 rounded-2xl text-sm whitespace-nowrap shadow-[0_0_15px_rgba(34,197,94,0.1)]";
            statusBadge.innerHTML = `<span class="status-dot" style="background: var(--accent-green); box-shadow: 0 0 8px var(--accent-green);"></span> Sniffing Live`;
        } else if (state === 'connecting') {
            statusBadge.className = "flex items-center text-amber-400 font-semibold bg-amber-500/10 border border-amber-500/20 px-3 py-1.5 rounded-2xl text-sm whitespace-nowrap shadow-[0_0_15px_rgba(245,158,11,0.1)]";
            statusBadge.innerHTML = `<span class="status-dot" style="background: var(--accent-amber); box-shadow: 0 0 8px var(--accent-amber);"></span> Connecting…`;
        } else {
            statusBadge.className = "flex items-center text-red-400 font-semibold bg-red-500/10 border border-red-500/20 px-3 py-1.5 rounded-2xl text-sm whitespace-nowrap shadow-[0_0_15px_rgba(239,68,68,0.1)]";
            statusBadge.innerHTML = `<span class="status-dot" style="background: var(--accent-red); box-shadow: 0 0 8px var(--accent-red); animation: none;"></span> Offline`;
        }
    }

    // ── WebSocket ─────────────────────────────────────────────
    function connectWebSocket() {
        if (!token) return;
        updateSystemStatus('connecting');
        wsConnection = new WebSocket(`${WS_BASE}/ws/traffic`);

        wsConnection.onopen = () => {
            console.log('[WS] Connected to live sniffer feed');
            updateSystemStatus('connected');
        };

        wsConnection.onmessage = (event) => {
            try {
                const message = JSON.parse(event.data);

                if (message.type === 'initial_state') {
                    const stateData = message.data;
                    totalPackets = stateData.total_packets || 0;
                    totalAnomalies = stateData.total_anomalies || 0;
                    alertCount = 0; // Reset count to prevent duplicates on reconnection
                    
                    const pStat = document.getElementById('stat-packets');
                    if (pStat) pStat.textContent = totalPackets;
                    
                    const aStat = document.getElementById('stat-anomalies');
                    if (aStat) aStat.textContent = totalAnomalies;
                    
                    // Render any initial alerts sent by backend
                    const list = document.getElementById('alerts-list');
                    if (list) list.innerHTML = '<li class="text-gray-600 text-sm text-center py-4">No alerts yet…</li>';
                    if (stateData.alerts && stateData.alerts.length) {
                        stateData.alerts.forEach(alert => {
                            displaySecurityAlert(alert);
                        });
                    }
                    
                    // Render any initial log history sent by backend
                    if (stateData.history && stateData.history.length) {
                        // Clear existing to avoid duplicate items
                        wsLogs = [];
                        allLogs = [];
                        stateData.history.forEach(log => {
                            log._geo = geoCache[log.source] || null;
                            wsLogs.push(log);
                            allLogs.unshift(log);
                        });
                        if (wsLogs.length > 50) wsLogs.splice(0, wsLogs.length - 50);
                        if (allLogs.length > 200) allLogs.splice(200);
                        
                        renderLogsTable(currentSearchTerm);
                        updateChart();
                    }
                    return;
                }

                if (message.type === 'traffic_update') {
                    const log = message.data;
                    totalPackets++;
                    ppsCounter++;
                    
                    const pStat = document.getElementById('stat-packets');
                    if (pStat) pStat.textContent = totalPackets;

                    if (log.class === 'Anomaly') {
                        totalAnomalies++;
                        const aStat = document.getElementById('stat-anomalies');
                        if (aStat) aStat.textContent = totalAnomalies;
                        
                        // Automatically trigger a security alert for ALL anomalies
                        displaySecurityAlert({
                            message: `Suspicious activity detected from ${log.source} (${log.reasons.join(', ')})`,
                            severity: log.threat_level > 0.7 ? 'High' : log.threat_level > 0.4 ? 'Medium' : 'Low',
                            timestamp: log.timestamp
                        });

                        // ONLY show Anomalies/Threats on the map
                        addMapMarker(log.source, log.reasons, log.class);
                    } else if (!geoCache[log.source]) {
                        // Background fetch for Normal traffic to populate table
                        fetchGeoIP(log.source);
                    }

                    // Attach geo info if cached
                    log._geo = geoCache[log.source] || null;

                    wsLogs.push(log);
                    allLogs.unshift(log);
                    if (wsLogs.length > 50) wsLogs.shift();
                    if (allLogs.length > 200) allLogs.pop();

                    // Throttled UI update for the table to prevent lag
                    if (!tableUpdatePending) {
                        tableUpdatePending = true;
                        requestAnimationFrame(() => {
                            try {
                                renderLogsTable(currentSearchTerm);
                            } finally {
                                tableUpdatePending = false;
                            }
                        });
                    }
                }

                if (message.type === 'alert') {
                    displaySecurityAlert(message.data);
                }
            } catch (err) {
                console.error('[WS] Parse error:', err);
            }
        };

        wsConnection.onclose = () => {
            console.warn('[WS] Disconnected. Reconnecting in 3s…');
            updateSystemStatus('disconnected');
            setTimeout(connectWebSocket, 3000);
        };

        wsConnection.onerror = (e) => {
            console.error('[WS] Error:', e);
            updateSystemStatus('disconnected');
        };
    }

    // ── Security Alerts Panel ─────────────────────────────────
    function displaySecurityAlert(alertData) {
        alertCount++;
        document.getElementById('stat-alerts').textContent       = alertCount;
        document.getElementById('stat-alerts-badge').textContent = alertCount;

        const list = document.getElementById('alerts-list');
        if (!list) return;

        // Remove placeholder
        const placeholder = list.querySelector('.text-gray-600');
        if (placeholder) placeholder.remove();

        const sev = (alertData.severity || 'Low').toLowerCase();
        const sevClass = sev === 'critical' ? 'severity-critical'
                       : sev === 'high'     ? 'severity-high'
                       : sev === 'medium'   ? 'severity-medium'
                       :                     'severity-low';

        const li = document.createElement('li');
        li.className = 'bg-red-900/10 border-l-4 border-red-600/60 p-3 rounded-lg';
        li.innerHTML = `
            <div class="flex flex-col gap-1">
                <span class="text-white font-medium text-xs">${escapeHTML(alertData.message)}</span>
                <div class="flex justify-between items-center mt-1">
                    <span class="severity-badge ${sevClass}">${escapeHTML(alertData.severity)}</span>
                    <span class="text-gray-600 text-xs">${new Date(typeof alertData.timestamp === 'number' ? alertData.timestamp * 1000 : alertData.timestamp).toLocaleTimeString()}</span>
                </div>
            </div>`;
        list.prepend(li);

        // Keep only last 20 alerts displayed
        while (list.children.length > 20) list.removeChild(list.lastChild);
    }

    // ── Log Table Rendering ───────────────────────────────────
    window.filterLogsFromSearch = function(term) {
        currentSearchTerm = term.toLowerCase().trim();
        // sync both search bars
        const top = document.getElementById('top-search-bar');
        const bot = document.getElementById('log-search-bar');
        if (top && top.value.toLowerCase() !== currentSearchTerm) top.value = term;
        if (bot && bot.value.toLowerCase() !== currentSearchTerm) bot.value = term;
        renderLogsTable(currentSearchTerm);
    };

    function renderLogsTable(filter) {
        const tbody = document.getElementById('logs-table-body');
        if (!tbody) return;

        let logs = allLogs;
        if (filter) {
            logs = logs.filter(l => {
                const geo = geoCache[l.source] || l._geo || {};
                const country = (geo.country || '').toLowerCase();
                const org     = (geo.org || '').toLowerCase();
                return (
                    (l.source     || '').toLowerCase().includes(filter) ||
                    (l.destination|| '').toLowerCase().includes(filter) ||
                    (l.proto      || '').toLowerCase().includes(filter) ||
                    (l.class      || '').toLowerCase().includes(filter) ||
                    country.includes(filter) ||
                    org.includes(filter)
                );
            });
        }

        tbody.innerHTML = '';
        if (!logs.length) {
            tbody.innerHTML = `<tr><td colspan="9" class="text-center text-gray-600 py-6">No matching packets.</td></tr>`;
            return;
        }

        logs.slice(0, 15).forEach(log => {
            const isAnomaly = log.class === 'Anomaly';
            const geo       = geoCache[log.source] || log._geo;
            const country   = geo ? `${geo.country}${geo.city ? ', ' + geo.city : ''}` : '—';
            const org       = geo ? geo.org : '';
            const threat    = parseFloat(log.threat_level) || 0;
            const threatClass = threat > 0.7 ? 'threat-high' : threat > 0.35 ? 'threat-medium' : 'threat-low';

            const row = document.createElement('tr');
            row.className = isAnomaly ? 'row-anomaly' : 'row-normal';
            row.innerHTML = `
                <td class="text-gray-400 font-mono" style="font-size:0.75rem">${new Date(typeof log.timestamp === 'number' ? log.timestamp * 1000 : log.timestamp).toLocaleTimeString()}</td>
                <td class="text-cyan-400 font-mono" style="font-size:0.75rem">${escapeHTML(log.source || '—')}</td>
                <td class="text-gray-400 font-mono" style="font-size:0.72rem">${escapeHTML((log.destination || '—').substring(0,20))}</td>
                <td><span class="text-xs font-mono bg-gray-800 px-2 py-0.5 rounded">${escapeHTML(log.proto || '—')}</span></td>
                <td class="text-gray-500 font-mono" style="font-size:0.72rem">${log.length || '—'}</td>
                <td style="font-size:0.72rem">
                    <span class="text-gray-300">${escapeHTML(country)}</span>
                    ${org ? `<br><span class="text-gray-600" style="font-size:0.68rem">${escapeHTML(org.substring(0,30))}</span>` : ''}
                </td>
                <td>
                    <span class="text-xs font-semibold ${isAnomaly ? 'text-red-400' : 'text-green-400'}">
                        ${isAnomaly ? '⚠ Anomaly' : '✓ Normal'}
                    </span>
                    ${log.reasons && log.reasons.length ? `<br><span class="text-gray-600" style="font-size:0.65rem">${escapeHTML(log.reasons.slice(0,2).join(', '))}</span>` : ''}
                </td>
                <td><span class="threat-pill ${threatClass}">${threat.toFixed(2)}</span></td>
                <td>
                    <button class="btn-block" onclick="window.blockIp('${escapeHTML(log.source)}')">Block</button>
                </td>`;
            tbody.appendChild(row);
        });
    }

    // ── Block IP ──────────────────────────────────────────────
    // ── Block IP ──────────────────────────────────────────────
    window.blockIp = async function (ip) {
        if (!confirm(`Are you sure you want to block IP: ${ip}?\nThis will create a Windows Firewall rule.`)) return;
        
        try {
            console.log(`[IDS] Requesting block for IP: ${ip}`);
            const res = await fetch(`${API_BASE}/block-ip`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ ip: ip })
            });
            
            const result = await res.json();
            
            if (res.ok) {
                console.log(`[IDS] IP ${ip} blocked successfully.`);
                displaySecurityAlert({
                    message: `SYSTEM ACTION: IP ${ip} has been blacklisted and blocked via Firewall.`,
                    severity: 'High',
                    timestamp: new Date().toISOString()
                });
                alert(`Success: ${ip} has been blocked.`);
            } else {
                console.error(`[IDS] Block failed:`, result);
                alert(`Block failed: ${result.detail || 'Access denied'}`);
            }
        } catch (e) {
            console.error('[IDS] Block request error:', e);
            alert('Communication error with security backend.');
        }
    };

    // ── Utility ───────────────────────────────────────────────
    function escapeHTML(str) {
        if (str == null) return '';
        return String(str).replace(/[&<>'"]/g, t => ({
            '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;'
        }[t]));
    }

    // Auto-show dashboard if already logged in (placed at the end to ensure all functions are defined)
    if (token) showDashboard();

}); // DOMContentLoaded