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
    let currentSecondMaxThreat = 0;       // maximum threat recorded in current 1s window
    let activeThreatMarkers = new Map();  // ip -> { marker, count, reasons, threatLevel, latestTime, geo }
    let pendingLookupPromises = new Map(); // ip -> Promise<geo>
    let recentAlertDedupe   = new Map();  // deduplication cache: key -> timestamp
    let geoCache            = {};         // IP → {country, org, city, lat, lon}
    let pendingLookups      = new Set();  // IPs currently being fetched
    let currentSearchTerm   = '';

    const API_BASE = 'http://localhost:8000';
    const WS_BASE  = 'ws://localhost:8000';

    console.log('[IDS] Script loaded, state initialized.');

    // ── PPS & Threat ticker — syncs chart in real-time ─────────
    function startPPSTicker() {
        if (ppsIntervalId) clearInterval(ppsIntervalId);
        ppsIntervalId = setInterval(() => {
            try {
                const now = new Date().toLocaleTimeString();
                
                // Push PPS & Timestamp label
                ppsHistory.push(ppsCounter);
                ppsLabels.push(now);
                
                // Push the maximum threat level recorded during this 1-second interval
                window._threatHistory.push(currentSecondMaxThreat);

                while (ppsHistory.length > 30) {
                    ppsHistory.shift();
                    ppsLabels.shift();
                    window._threatHistory.shift();
                }

                const ppsDisplay = document.getElementById('stat-pps');
                if (ppsDisplay) ppsDisplay.textContent = ppsCounter;
                
                // Reset packet counter for next second
                ppsCounter = 0;

                // Smoothly decay threat level if no new threat occurs (prevents artificial flatlining)
                currentSecondMaxThreat = Math.max(0, currentSecondMaxThreat * 0.35);
                if (currentSecondMaxThreat < 0.04) currentSecondMaxThreat = 0;

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
                        borderColor: 'rgba(59, 130, 246, 0.9)',
                        backgroundColor: 'rgba(37, 99, 235, 0.08)',
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
                        borderColor: 'rgba(37, 99, 235, 0.4)',
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
                        ticks: { color: 'rgba(96, 165, 250, 0.8)', font: { size: 10 } },
                        grid: { drawOnChartArea: false },
                        title: { display: true, text: 'PPS', color: 'rgba(96, 165, 250, 0.6)', font: { size: 10 } }
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

    // ── Helper: Extract IP from Alert Object or Message ──────
    function extractIP(data) {
        if (!data) return '127.0.0.1';
        if (data.source) return data.source;
        if (data.ip) return data.ip;
        if (data.src_ip) return data.src_ip;
        const msg = String(data.message || '');
        const match = msg.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
        return match ? match[0] : '127.0.0.1';
    }

    // ── Robust Non-Blocking GeoIP Lookup with Promise Caching ─
    async function fetchGeoIP(ip) {
        if (!ip) return null;
        if (geoCache[ip]) return geoCache[ip];
        if (pendingLookupPromises.has(ip)) {
            return await pendingLookupPromises.get(ip);
        }

        const lookupPromise = (async () => {
            try {
                const res = await fetch(`${API_BASE}/geo-ip/${encodeURIComponent(ip)}`);
                if (res.ok) {
                    const geo = await res.json();
                    if (geo && typeof geo.lat === 'number' && typeof geo.lon === 'number' && (geo.lat !== 0 || geo.lon !== 0)) {
                        geoCache[ip] = geo;
                        return geo;
                    }
                }
            } catch (e) {
                console.warn(`[IDS] Geo-IP lookup error for ${ip}:`, e);
            }

            // Fallback deterministic coordinates so EVERY threat has a visible marker on map
            const h = ip.split('').reduce((acc, c) => acc + c.charCodeAt(0), 0);
            const fallback = {
                lat: 20.0 + ((h * 13) % 40) - 20,
                lon: ((h * 31) % 360) - 180,
                country: 'Remote Host',
                city: ip,
                org: 'Network Threat Origin'
            };
            geoCache[ip] = fallback;
            return fallback;
        })();

        pendingLookupPromises.set(ip, lookupPromise);
        try {
            const result = await lookupPromise;
            if (!tableUpdatePending) {
                tableUpdatePending = true;
                requestAnimationFrame(() => {
                    try { renderLogsTable(currentSearchTerm); } finally { tableUpdatePending = false; }
                });
            }
            return result;
        } finally {
            pendingLookupPromises.delete(ip);
        }
    }

    // ── Build Interactive Popup for Live Threat Map ───────────
    function buildPopupHtml(ip, geo, reasons, threatLevel, count, timeStr) {
        const tNum = typeof threatLevel === 'number' ? threatLevel : 0.8;
        const sevName = tNum > 0.8 ? 'CRITICAL' : tNum > 0.5 ? 'HIGH' : 'MEDIUM';
        const sevBg = tNum > 0.8 
            ? 'background:rgba(239,68,68,0.25); color:#fca5a5; border:1px solid rgba(239,68,68,0.5);' 
            : tNum > 0.5 
            ? 'background:rgba(249,115,22,0.25); color:#fdba74; border:1px solid rgba(249,115,22,0.5);' 
            : 'background:rgba(234,179,8,0.25); color:#fde047; border:1px solid rgba(234,179,8,0.5);';

        const safeReasons = (Array.isArray(reasons) ? reasons : [reasons || 'Anomaly']).slice(0, 4);
        const reasonsHtml = safeReasons.map(r => 
            `<span style="display:inline-block; background:rgba(255,255,255,0.07); border:1px solid rgba(255,255,255,0.1); padding:2px 7px; border-radius:5px; margin:2px 3px 2px 0; color:#fca5a5; font-size:10.5px;">${escapeHTML(r)}</span>`
        ).join('');

        return `
            <div class="threat-popup-body" style="padding:4px 2px; min-width:210px;">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                    <span class="popup-badge" style="${sevBg}">${sevName} THREAT</span>
                    <span style="font-size:10px; color:#94a3b8; font-family:monospace;">${timeStr}</span>
                </div>
                <div style="font-weight:700; font-size:13.5px; color:#f87171; font-family:monospace; margin-bottom:4px; display:flex; align-items:center; gap:5px;">
                    <span>🚨</span> <span>${escapeHTML(ip)}</span>
                </div>
                <div style="color:#cbd5e1; font-size:11px; margin-bottom:2px;">
                    📍 <strong>${escapeHTML(geo.city || 'LAN')}, ${escapeHTML(geo.country || 'Host')}</strong>
                </div>
                <div style="color:#64748b; font-size:10px; margin-bottom:6px;">
                    🏢 ${escapeHTML(geo.org || 'Local Subnet')}
                </div>
                <div style="margin-bottom:8px;">
                    <div style="font-size:10px; color:#94a3b8; margin-bottom:3px;">
                        Threat Detection (${count} incident${count > 1 ? 's' : ''}):
                    </div>
                    <div>${reasonsHtml}</div>
                </div>
                <div class="threat-popup-actions">
                    <button type="button" class="popup-btn popup-btn-locate" onclick="window.locateAlertForIP('${escapeHTML(ip)}')">
                        <i class="fas fa-bell"></i> Locate Alert
                    </button>
                    <button type="button" class="popup-btn popup-btn-block" onclick="window.blockIP('${escapeHTML(ip)}')">
                        <i class="fas fa-shield-alt"></i> Block IP
                    </button>
                </div>
            </div>
        `;
    }

    // ── Add/Update Live Threat Radar Marker on Map ─────────────
    async function addMapMarker(ip, reasons, type, threatLevel = 0.8, isInitial = false) {
        if (!threatMap || !ip) return null;

        const isAnomaly = type === 'Anomaly' || type === 'Threat' || threatLevel > 0.4;
        const geo = await fetchGeoIP(ip);
        if (!geo) return null;

        const tNum = typeof threatLevel === 'number' ? threatLevel : 0.8;
        const sevClass = tNum > 0.8 ? 'critical' : tNum > 0.5 ? 'high' : 'medium';
        const reasonsList = Array.isArray(reasons) ? reasons : (reasons ? [reasons] : ['Suspicious Activity']);

        // Check if marker already exists on map for this IP
        if (activeThreatMarkers.has(ip)) {
            const entry = activeThreatMarkers.get(ip);
            entry.count++;
            entry.threatLevel = Math.max(entry.threatLevel, tNum);
            reasonsList.forEach(r => {
                if (!entry.reasons.includes(r)) entry.reasons.push(r);
            });
            entry.latestTime = new Date().toLocaleTimeString();

            // Refresh popup content with new incident count & reasons
            entry.marker.setPopupContent(buildPopupHtml(ip, geo, entry.reasons, entry.threatLevel, entry.count, entry.latestTime));

            if (!isInitial) {
                // Re-trigger radar pulse animation
                const markerEl = entry.marker.getElement();
                if (markerEl) {
                    const wave = markerEl.querySelector('.threat-radar-wave');
                    if (wave) {
                        wave.style.animation = 'none';
                        void wave.offsetHeight; // trigger reflow
                        wave.style.animation = 'threat-radar-ping 1.8s cubic-bezier(0, 0, 0.2, 1) infinite';
                    }
                }
                if (tNum >= 0.7) {
                    threatMap.panTo([geo.lat, geo.lon], { animate: true, duration: 0.8 });
                }
            }
            return entry.marker;
        }

        // Create new interactive radar marker
        const markerIcon = L.divIcon({
            className: 'threat-radar-marker',
            html: `
                <div class="threat-radar-wrap" title="Threat from ${escapeHTML(ip)}">
                    <div class="threat-radar-wave ${sevClass}"></div>
                    <div class="threat-radar-core ${sevClass}"></div>
                </div>
            `,
            iconSize: [40, 40],
            iconAnchor: [20, 20]
        });

        const timeStr = new Date().toLocaleTimeString();
        const popupHtml = buildPopupHtml(ip, geo, reasonsList, tNum, 1, timeStr);

        const marker = L.marker([geo.lat, geo.lon], { icon: markerIcon })
            .addTo(threatMap)
            .bindPopup(popupHtml, { minWidth: 220, maxWidth: 300 });

        // Map marker click synchronizes directly with Security Alerts list
        marker.on('click', () => {
            window.locateAlertForIP(ip);
        });

        activeThreatMarkers.set(ip, {
            marker,
            count: 1,
            reasons: [...reasonsList],
            threatLevel: tNum,
            latestTime: timeStr,
            geo
        });

        if (!isInitial && tNum >= 0.6) {
            threatMap.panTo([geo.lat, geo.lon], { animate: true, duration: 0.8 });
        }

        return marker;
    }

    // ── Interactive Sync: Focus Threat on Map From Alert Click ─
    window.focusThreatOnMap = function(ip) {
        if (!threatMap || !ip) return;
        const entry = activeThreatMarkers.get(ip);
        if (entry && entry.marker && entry.geo) {
            threatMap.flyTo([entry.geo.lat, entry.geo.lon], Math.max(threatMap.getZoom(), 5), {
                duration: 0.8
            });
            setTimeout(() => {
                entry.marker.openPopup();
            }, 850);
        } else {
            addMapMarker(ip, ['Threat Detected'], 'Anomaly', 0.8, false).then(marker => {
                if (marker) marker.openPopup();
            });
        }
    };

    // ── Interactive Sync: Highlight Alert in List From Marker Click ──
    window.locateAlertForIP = function(ip) {
        const list = document.getElementById('alerts-list');
        if (!list || !ip) return;
        const alerts = list.querySelectorAll(`li[data-ip="${ip}"]`);
        if (alerts.length > 0) {
            const target = alerts[0];
            target.scrollIntoView({ behavior: 'smooth', block: 'center' });
            target.classList.remove('focused-threat');
            void target.offsetWidth; // trigger reflow
            target.classList.add('focused-threat');
            setTimeout(() => target.classList.remove('focused-threat'), 2500);
        }
    };

    // ── Master Synchronizer: Syncs Map, Chart, and Alerts ──────
    async function syncThreatEvent(eventData, isInitial = false) {
        if (!eventData) return;

        const ip = extractIP(eventData);
        const reasons = eventData.reasons || (eventData.message ? [eventData.message] : ['Suspicious Activity']);
        const sev = eventData.severity || (eventData.threat_level > 0.7 ? 'High' : eventData.threat_level > 0.4 ? 'Medium' : 'Low');
        const threatVal = typeof eventData.threat_level === 'number' 
            ? eventData.threat_level 
            : (sev.toLowerCase() === 'critical' ? 1.0 : sev.toLowerCase() === 'high' ? 0.85 : 0.5);

        // Deduplicate rapid duplicate alerts within 1.5 seconds
        const dedupeKey = `${ip}_${eventData.message}`;
        const nowMs = Date.now();
        if (!isInitial && recentAlertDedupe.has(dedupeKey) && (nowMs - recentAlertDedupe.get(dedupeKey)) < 1500) {
            return;
        }
        recentAlertDedupe.set(dedupeKey, nowMs);

        // 1. Plot / Update Threat Radar on Live Threat Mapping
        addMapMarker(ip, reasons, 'Anomaly', threatVal, isInitial);

        // 2. Synchronize Live Traffic & Threat Level Chart Spike
        if (!isInitial) {
            currentSecondMaxThreat = Math.max(currentSecondMaxThreat, threatVal);
            if (window._threatHistory && window._threatHistory.length > 0) {
                window._threatHistory[window._threatHistory.length - 1] = Math.max(
                    window._threatHistory[window._threatHistory.length - 1] || 0,
                    threatVal
                );
            }
            updateChart();
        }

        // 3. Render Interactive Item in Security Alerts Panel
        displaySecurityAlert({
            source: ip,
            message: eventData.message || `Suspicious activity detected from ${ip} (${reasons.join(', ')})`,
            severity: sev,
            threat_level: threatVal,
            reasons: reasons,
            timestamp: eventData.timestamp || new Date().toISOString()
        }, isInitial);
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
                    ? ` <span class="px-2 py-0.5 text-xs bg-blue-500/20 text-blue-300 font-bold rounded border border-blue-500/30 uppercase tracking-wider ml-1">THIS PC</span>`
                    : '';
                const cleanName = device.name ? device.name.replace(/\s*\(This PC\)/i, '') : '';
                const nameDisplay = cleanName && cleanName !== 'Unknown Device' 
                    ? ` — <span class="text-blue-400 font-semibold">${escapeHTML(cleanName)}</span>` 
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
                    alertCount = 0; // Reset count to accurately reflect state
                    
                    const pStat = document.getElementById('stat-packets');
                    if (pStat) pStat.textContent = totalPackets;
                    
                    const aStat = document.getElementById('stat-anomalies');
                    if (aStat) aStat.textContent = totalAnomalies;
                    
                    const list = document.getElementById('alerts-list');
                    if (list) list.innerHTML = '';
                    
                    // Synchronize all existing alerts with Threat Map, Alerts Panel, and Chart
                    if (stateData.alerts && stateData.alerts.length) {
                        stateData.alerts.forEach(alert => {
                            syncThreatEvent({
                                source: alert.source || extractIP(alert),
                                message: alert.message,
                                severity: alert.severity || 'Medium',
                                threat_level: alert.threat_level || 0.75,
                                reasons: alert.reasons || [alert.message],
                                timestamp: alert.timestamp
                            }, true /* isInitial */);
                        });
                    } else {
                        if (list) list.innerHTML = '<li class="text-gray-600 text-sm text-center py-4">No alerts yet…</li>';
                    }
                    
                    // Synchronize log history & map markers for previous anomalies
                    if (stateData.history && stateData.history.length) {
                        wsLogs = [];
                        allLogs = [];
                        stateData.history.forEach(log => {
                            log._geo = geoCache[log.source] || null;
                            wsLogs.push(log);
                            allLogs.unshift(log);
                            if (log.class === 'Anomaly') {
                                addMapMarker(log.source, log.reasons, log.class, log.threat_level || 0.75, true);
                            }
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
                        
                        // Synchronously update Threat Map, Threat Level Chart, and Security Alerts
                        syncThreatEvent({
                            source: log.source,
                            reasons: log.reasons,
                            threat_level: log.threat_level,
                            severity: log.threat_level > 0.7 ? 'High' : log.threat_level > 0.4 ? 'Medium' : 'Low',
                            message: `Suspicious activity detected from ${log.source} (${(log.reasons || []).join(', ')})`,
                            timestamp: log.timestamp
                        }, false);
                    } else if (!geoCache[log.source]) {
                        // Background fetch for normal traffic
                        fetchGeoIP(log.source);
                    }

                    log._geo = geoCache[log.source] || null;

                    wsLogs.push(log);
                    allLogs.unshift(log);
                    if (wsLogs.length > 50) wsLogs.shift();
                    if (allLogs.length > 200) allLogs.pop();

                    // Throttled UI update for log table
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
                    // Synchronously update Threat Map, Threat Level Chart, and Security Alerts
                    syncThreatEvent(message.data, false);
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
    function displaySecurityAlert(alertData, isInitial = false) {
        alertCount++;
        const statA = document.getElementById('stat-alerts');
        const statB = document.getElementById('stat-alerts-badge');
        if (statA) statA.textContent = alertCount;
        if (statB) statB.textContent = alertCount;

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

        const ip = alertData.source || extractIP(alertData);
        const alertId = 'alert-' + Math.random().toString(36).substr(2, 8);

        const li = document.createElement('li');
        li.id = alertId;
        li.dataset.ip = ip;
        li.className = 'alert-card-interactive bg-red-950/20 border border-red-500/20 border-l-4 border-l-red-500 p-3 rounded-xl mb-2.5';
        li.innerHTML = `
            <div class="flex flex-col gap-1.5">
                <div class="flex items-start justify-between gap-2">
                    <span class="text-slate-200 font-medium text-xs leading-snug">${escapeHTML(alertData.message)}</span>
                    <button type="button" class="text-[11px] text-blue-400 hover:text-blue-300 font-mono bg-blue-500/10 hover:bg-blue-500/20 px-2 py-0.5 rounded transition flex items-center gap-1 shrink-0" title="Locate threat on map">
                        <i class="fas fa-crosshairs text-[10px]"></i> Map
                    </button>
                </div>
                <div class="flex justify-between items-center mt-0.5 pt-1 border-t border-white/5">
                    <div class="flex items-center gap-1.5">
                        <span class="severity-badge ${sevClass}">${escapeHTML(alertData.severity || 'Medium')}</span>
                        <span class="text-[11px] font-mono text-slate-400 bg-white/5 px-1.5 py-0.5 rounded">${escapeHTML(ip)}</span>
                    </div>
                    <span class="text-slate-500 text-[11px]">${new Date(typeof alertData.timestamp === 'number' ? alertData.timestamp * 1000 : alertData.timestamp).toLocaleTimeString()}</span>
                </div>
            </div>`;

        // Interactive sync: Clicking alert highlights and centers the threat on the map!
        li.addEventListener('click', () => {
            window.focusThreatOnMap(ip);
        });

        list.prepend(li);

        // Keep last 30 alerts displayed
        while (list.children.length > 30) list.removeChild(list.lastChild);
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
                <td class="text-blue-400 font-mono" style="font-size:0.75rem">${escapeHTML(log.source || '—')}</td>
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