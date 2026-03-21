// ============================================================================
// HoneyPot Dashboard - Real-Time JavaScript
// ============================================================================

// Global state
let socket;
let portChart;
let timelineChart;
let statsUpdateInterval;
let attackMap;
let previousStats = {};
let allEvents = []; // Store all events for filtering
let activeFilters = {
    ip: '',
    port: '',
    event: '',
    time: '24h' // Default to 24h
};

// ============================================================================
// Initialization
// ============================================================================

document.addEventListener('DOMContentLoaded', function() {
    console.log('🐻 HoneyPot Dashboard Loading...');
    
    // Initialize WebSocket connection
    initWebSocket();
    
    // Load initial data
    loadStats();
    
    // Set up auto-refresh every 5 seconds
    statsUpdateInterval = setInterval(loadStats, 5000);
    
    // Initialize charts
    initCharts();
    loadMapData();
    
    // Auto-refresh map every 5 seconds
    setInterval(() => {
        console.log('🔄 Auto-refreshing map...');
        loadMapData();
    }, 5000);
    
    // Setup filter listeners
    setupFilters();
    
    console.log('✅ Dashboard Ready');
});

// ============================================================================
// WebSocket Connection
// ============================================================================

function initWebSocket() {
    socket = io();
    
    socket.on('connect', function() {
        console.log('✅ WebSocket Connected');
        updateConnectionStatus(true);
    });
    
    socket.on('disconnect', function() {
        console.log('❌ WebSocket Disconnected');
        updateConnectionStatus(false);
    });
    
    socket.on('connected', function(data) {
        console.log('Server says:', data);
    });
    
    socket.on('stats_update', function(stats) {
        console.log('📊 Stats update received:', stats);
        updateDashboard(stats);
    });
    
    socket.on('new_attack', function(attack) {
        console.log('🚨 New attack:', attack);
        addToLiveFeed(attack);
        
        // Immediately refresh map (no delay)
        console.log('🗺️ New attack detected - refreshing map immediately');
        setTimeout(() => loadMapData(), 500);
    });
}

function updateConnectionStatus(connected) {
    const statusEl = document.getElementById('connectionStatus');
    if (connected) {
        statusEl.innerHTML = '<span class="dot"></span> Connected';
        statusEl.classList.add('connected');
        statusEl.classList.remove('disconnected');
    } else {
        statusEl.innerHTML = '<span class="dot"></span> Disconnected';
        statusEl.classList.add('disconnected');
        statusEl.classList.remove('connected');
    }
}

// ============================================================================
// Data Loading
// ============================================================================

async function loadStats() {
    try {
        // Build query string with filters
        const params = new URLSearchParams();
        if (activeFilters.ip) params.append('ip', activeFilters.ip);
        if (activeFilters.port) params.append('port', activeFilters.port);
        if (activeFilters.event) params.append('event_type', activeFilters.event);
        if (activeFilters.time) params.append('time_range', activeFilters.time);
        
        const url = `/api/stats?${params.toString()}`;
        const response = await fetch(url);
        const stats = await response.json();
        
        // Store all events for frontend filtering
        if (stats.recent_events) {
            allEvents = stats.recent_events;
        }
        
        updateDashboard(stats);
    } catch (error) {
        console.error('Error loading stats:', error);
    }
}

function updateDashboard(stats) {
    // Update stat cards with smooth counting animation ONLY if values changed
    updateStatIfChanged('totalAttacks', stats.total_attacks || 0);
    updateStatIfChanged('sshAttacks', stats.ports['22'] || 0);
    updateStatIfChanged('telnetAttacks', stats.ports['23'] || 0);
    updateStatIfChanged('httpAttacks', stats.ports['80'] || 0);
    updateStatIfChanged('ftpAttacks', stats.ports['21'] || 0);
    updateStatIfChanged('credsCaptured', stats.credentials_captured || 0);
    
    // Update top IPs
    updateTopIPs(stats.top_ips || []);
    
    // Update port chart
    updatePortChart(stats.ports || {});
    
    // Update timeline chart
    updateTimelineChart(stats.recent_events || []);

// Helper to only update and animate when value changes
function updateStatIfChanged(id, newValue) {
    const element = document.getElementById(id);
    if (!element) return;
    
    const currentValue = parseInt(element.textContent) || 0;
    
    // Only animate if value actually changed
    if (currentValue !== newValue) {
        animateValue(id, currentValue, newValue, 600);
    }
}

// Smooth number counter animation
function animateValue(id, start, end, duration) {
    const element = document.getElementById(id);
    if (!element) return;
    
    const range = end - start;
    const increment = range / (duration / 16);
    let current = start;
    
    const timer = setInterval(() => {
        current += increment;
        if ((increment > 0 && current >= end) || (increment < 0 && current <= end)) {
            current = end;
            clearInterval(timer);
        }
        element.textContent = Math.floor(current);
    }, 16);
}
    
    // Update recent events in feed
    if (stats.recent_events && stats.recent_events.length > 0) {
        updateLiveFeed(stats.recent_events);
    }
    
    // Update timestamp
    updateTimestamp();
}

// ============================================================================
// Charts
// ============================================================================

function initCharts() {
    // Port Distribution Chart (Horizontal Bar)
    const ctx = document.getElementById('portChart');
    
    portChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['SSH (22)', 'Telnet (23)', 'HTTP (80)', 'FTP (21)'],
            datasets: [{
                label: 'Attacks',
                data: [0, 0, 0, 0],
                backgroundColor: [
                    'rgba(0, 212, 255, 0.7)',
                    'rgba(0, 255, 65, 0.7)',
                    'rgba(255, 215, 0, 0.7)',
                    'rgba(255, 0, 64, 0.7)'
                ],
                borderColor: [
                    'rgba(0, 212, 255, 1)',
                    'rgba(0, 255, 65, 1)',
                    'rgba(255, 215, 0, 1)',
                    'rgba(255, 0, 64, 1)'
                ],
                borderWidth: 2
            }]
        },
        options: {
            indexAxis: 'y', // Horizontal bars
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                x: {
                    beginAtZero: true,
                    grid: {
                        color: 'rgba(0, 255, 65, 0.1)'
                    },
                    ticks: {
                        color: '#a0a0a0',
                        font: {
                            family: "'Courier New', monospace",
                            size: 10
                        }
                    }
                },
                y: {
                    grid: {
                        display: false
                    },
                    ticks: {
                        color: '#e0e0e0',
                        font: {
                            family: "'Courier New', monospace",
                            size: 11
                        }
                    }
                }
            }
        }
    });
    
    // Timeline Chart (Line)
    const timelineCtx = document.getElementById('timelineChart');
    
    timelineChart = new Chart(timelineCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Attacks',
                data: [],
                borderColor: 'rgba(0, 255, 65, 1)',
                backgroundColor: 'rgba(0, 255, 65, 0.1)',
                borderWidth: 2,
                fill: true,
                tension: 0.4,
                pointRadius: 4,
                pointBackgroundColor: 'rgba(0, 255, 65, 1)',
                pointBorderColor: '#fff',
                pointBorderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                x: {
                    grid: {
                        color: 'rgba(0, 255, 65, 0.1)'
                    },
                    ticks: {
                        color: '#a0a0a0',
                        font: {
                            family: "'Courier New', monospace",
                            size: 10
                        }
                    }
                },
                y: {
                    beginAtZero: true,
                    grid: {
                        color: 'rgba(0, 255, 65, 0.1)'
                    },
                    ticks: {
                        color: '#a0a0a0',
                        font: {
                            family: "'Courier New', monospace",
                            size: 10
                        }
                    }
                }
            }
        }
    });
}

function updatePortChart(ports) {
    if (!portChart) return;
    
    const data = [
        ports['22'] || 0,
        ports['23'] || 0,
        ports['80'] || 0,
        ports['21'] || 0
    ];
    
    portChart.data.datasets[0].data = data;
    portChart.update();
}

function updateTimelineChart(events) {
    if (!timelineChart || !events || events.length === 0) return;
    
    const now = new Date();
    const timeRange = activeFilters.time || '24h';
    const labels = [];
    const data = [];
    
    if (timeRange === '12h') {
        // Show last 12 hours
        const hourlyData = {};
        for (let i = 11; i >= 0; i--) {
            const hour = new Date(now - i * 3600000);
            const hourKey = hour.getHours();
            hourlyData[hourKey] = 0;
        }
        
        events.forEach(event => {
            try {
                const eventDate = new Date(event.timestamp);
                const hoursDiff = Math.floor((now - eventDate) / 3600000);
                if (hoursDiff >= 0 && hoursDiff < 12) {
                    const hour = eventDate.getHours();
                    hourlyData[hour] = (hourlyData[hour] || 0) + 1;
                }
            } catch (e) {}
        });
        
        for (let i = 11; i >= 0; i--) {
            const hour = new Date(now - i * 3600000);
            const hourKey = hour.getHours();
            labels.push(`${hourKey}:00`);
            data.push(hourlyData[hourKey] || 0);
        }
        
    } else if (timeRange === '24h') {
        // Show last 24 hours
        const hourlyData = {};
        for (let i = 23; i >= 0; i--) {
            const hour = new Date(now - i * 3600000);
            const hourKey = hour.getHours();
            hourlyData[hourKey] = 0;
        }
        
        events.forEach(event => {
            try {
                const eventDate = new Date(event.timestamp);
                const hoursDiff = Math.floor((now - eventDate) / 3600000);
                if (hoursDiff >= 0 && hoursDiff < 24) {
                    const hour = eventDate.getHours();
                    hourlyData[hour] = (hourlyData[hour] || 0) + 1;
                }
            } catch (e) {}
        });
        
        for (let i = 23; i >= 0; i--) {
            const hour = new Date(now - i * 3600000);
            const hourKey = hour.getHours();
            labels.push(`${hourKey}:00`);
            data.push(hourlyData[hourKey] || 0);
        }
        
    } else if (timeRange === '7d') {
        // Show last 7 days
        const dailyData = {};
        for (let i = 6; i >= 0; i--) {
            const day = new Date(now.getTime() - i * 86400000);
            const dayKey = day.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
            dailyData[dayKey] = 0;
        }
        
        events.forEach(event => {
            try {
                const eventDate = new Date(event.timestamp);
                const daysDiff = Math.floor((now - eventDate) / 86400000);
                if (daysDiff >= 0 && daysDiff < 7) {
                    const dayKey = eventDate.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
                    dailyData[dayKey] = (dailyData[dayKey] || 0) + 1;
                }
            } catch (e) {}
        });
        
        for (let i = 6; i >= 0; i--) {
            const day = new Date(now.getTime() - i * 86400000);
            const dayKey = day.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
            labels.push(dayKey);
            data.push(dailyData[dayKey] || 0);
        }
        
    } else if (timeRange === '30d') {
        // Show last 30 days
        const dailyData = {};
        for (let i = 29; i >= 0; i--) {
            const day = new Date(now.getTime() - i * 86400000);
            const dayKey = day.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
            dailyData[dayKey] = 0;
        }
        
        events.forEach(event => {
            try {
                const eventDate = new Date(event.timestamp);
                const daysDiff = Math.floor((now - eventDate) / 86400000);
                if (daysDiff >= 0 && daysDiff < 30) {
                    const dayKey = eventDate.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
                    dailyData[dayKey] = (dailyData[dayKey] || 0) + 1;
                }
            } catch (e) {}
        });
        
        // Show every 3rd day to avoid crowding
        for (let i = 29; i >= 0; i -= 3) {
            const day = new Date(now.getTime() - i * 86400000);
            const dayKey = day.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
            labels.push(dayKey);
            // Sum up the 3 days
            let sum = 0;
            for (let j = 0; j < 3 && (i - j) >= 0; j++) {
                const d = new Date(now.getTime() - (i - j) * 86400000);
                const k = d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
                sum += dailyData[k] || 0;
            }
            data.push(sum);
        }
        
    } else {
        // 'all' - group by day, show last 30 days
        const dailyData = {};
        for (let i = 29; i >= 0; i--) {
            const day = new Date(now.getTime() - i * 86400000);
            const dayKey = day.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
            dailyData[dayKey] = 0;
        }
        
        events.forEach(event => {
            try {
                const eventDate = new Date(event.timestamp);
                const dayKey = eventDate.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
                dailyData[dayKey] = (dailyData[dayKey] || 0) + 1;
            } catch (e) {}
        });
        
        for (let i = 29; i >= 0; i -= 3) {
            const day = new Date(now.getTime() - i * 86400000);
            const dayKey = day.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
            labels.push(dayKey);
            data.push(dailyData[dayKey] || 0);
        }
    }
    
    timelineChart.data.labels = labels;
    timelineChart.data.datasets[0].data = data;
    timelineChart.update();
}

// ============================================================================
// Top IPs
// ============================================================================

function updateTopIPs(topIPs) {
    const container = document.getElementById('topIPs');
    
    if (!topIPs || topIPs.length === 0) {
        container.innerHTML = `
            <div class="ip-item">
                <span class="ip-address">No attacks yet</span>
                <span class="ip-count">0 hits</span>
            </div>
        `;
        return;
    }
    
    // Check if IPs actually changed
    const currentIPs = Array.from(container.querySelectorAll('.ip-address')).map(el => el.textContent);
    const newIPs = topIPs.slice(0, 10).map(item => item.ip);
    
    // Only update if the list changed
    if (JSON.stringify(currentIPs) === JSON.stringify(newIPs)) {
        // Just update counts without re-rendering
        topIPs.slice(0, 10).forEach((item, index) => {
            const countEl = container.children[index]?.querySelector('.ip-count');
            if (countEl) {
                countEl.textContent = `${item.count} hits`;
            }
        });
        return;
    }
    
    // Full re-render only if IPs changed
    container.innerHTML = topIPs.slice(0, 10).map((item, index) => `
        <div class="ip-item" style="--delay: ${index}">
            <span class="ip-address">${item.ip}</span>
            <span class="ip-count">${item.count} hits</span>
        </div>
    `).join('');
}

// ============================================================================
// Live Feed
// ============================================================================

function updateLiveFeed(events) {
    const feed = document.getElementById('liveFeed');
    
    // Clear placeholder
    const firstItem = feed.querySelector('.feed-item .feed-time');
    if (firstItem && firstItem.textContent === '--:--:--') {
        feed.innerHTML = '';
    }
    
    if (!events || events.length === 0) return;
    
    // Get existing events to avoid re-rendering duplicates
    const existingTimestamps = Array.from(feed.querySelectorAll('.feed-item'))
        .map(item => item.dataset.timestamp);
    
    // Add recent events (limit to last 20)
    const recentEvents = events.slice(0, 20);
    
    // Only add new events
    recentEvents.forEach(event => {
        if (existingTimestamps.includes(event.timestamp)) return;
        
        const time = new Date(event.timestamp).toLocaleTimeString();
        const isCredential = event.event_type === 'SSH_LOGIN' || 
                           event.event_type === 'CREDENTIAL_SUBMISSION' || 
                           event.credentials;
        const isCommand = event.event_type?.startsWith('CMD:');
        
        let text = '';
        let icon = '';
        
        // Format based on event type
        if (isCommand) {
            icon = '💻';
            const command = event.event_type.replace('CMD: ', '');
            text = `<span class="feed-ip">${event.source_ip}</span> executed: <code>${command}</code>`;
        } else if (isCredential) {
            icon = '🔑';
            if (event.credentials) {
                text = `<span class="feed-ip">${event.source_ip}</span> 🚨 Credentials: <strong>${event.credentials.username}</strong> / <strong>${event.credentials.password}</strong>`;
            } else {
                text = `<span class="feed-ip">${event.source_ip}</span> logged in via ${event.service.toUpperCase()}`;
            }
        } else {
            icon = '🎯';
            text = `<span class="feed-ip">${event.source_ip}</span> [${event.service?.toUpperCase() || 'UNKNOWN'}] ${event.event_type || 'Connection'}`;
        }
        
        if (event.details && event.details.length > 0 && !isCommand) {
            text += ` <span class="feed-detail">${event.details.substring(0, 60)}</span>`;
        }
        
        const feedItem = document.createElement('div');
        feedItem.className = `feed-item ${isCredential ? 'credential' : ''} ${isCommand ? 'command' : ''}`;
        feedItem.dataset.timestamp = event.timestamp;
        feedItem.innerHTML = `
            <span class="feed-icon">${icon}</span>
            <span class="feed-time">${time}</span>
            <span class="feed-text">${text}</span>
        `;
        
        feed.insertBefore(feedItem, feed.firstChild);
    });
    
    // Keep only last 50 items
    while (feed.children.length > 50) {
        feed.removeChild(feed.lastChild);
    }
}

function addToLiveFeed(attack) {
    const feed = document.getElementById('liveFeed');
    const time = new Date().toLocaleTimeString();
    
    const isCredential = attack.credentials || attack.event_type === 'CREDENTIAL_SUBMISSION' || attack.event_type === 'SSH_LOGIN';
    const isCommand = attack.event_type?.startsWith('CMD:');
    
    let text = '';
    let icon = '';
    
    if (isCommand) {
        icon = '💻';
        const command = attack.event_type.replace('CMD: ', '');
        text = `<span class="feed-ip">${attack.source_ip}</span> executed: <code>${command}</code>`;
    } else if (isCredential) {
        icon = '🔑';
        text = `<span class="feed-ip">${attack.source_ip}</span> 🚨 Login detected`;
    } else {
        icon = '🎯';
        text = `<span class="feed-ip">${attack.source_ip}</span> [${attack.service?.toUpperCase()}] ${attack.event_type}`;
    }
    
    const feedItem = document.createElement('div');
    feedItem.className = `feed-item ${isCredential ? 'credential' : ''} ${isCommand ? 'command' : ''}`;
    feedItem.dataset.timestamp = attack.timestamp || new Date().toISOString();
    feedItem.innerHTML = `
        <span class="feed-icon">${icon}</span>
        <span class="feed-time">${time}</span>
        <span class="feed-text">${text}</span>
    `;
    
    feed.insertBefore(feedItem, feed.firstChild);
    
    // Keep only last 50 items
    while (feed.children.length > 50) {
        feed.removeChild(feed.lastChild);
    }
}

function clearFeed() {
    const feed = document.getElementById('liveFeed');
    feed.innerHTML = `
        <div class="feed-item">
            <span class="feed-time">--:--:--</span>
            <span class="feed-text">Feed cleared. Waiting for new attacks...</span>
        </div>
    `;
}

// ============================================================================
// Utilities
// ============================================================================

function updateTimestamp() {
    const now = new Date();
    const timeString = now.toLocaleTimeString();
    document.getElementById('lastUpdate').textContent = timeString;
}

// ============================================================================
// Map Functions (GeoIP - Phase 3)
// ============================================================================

async function loadMapData() {
    const placeholder = document.getElementById('mapPlaceholder');
    const mapElement = document.getElementById('attackMap');
    
    // Show loading state
    placeholder.innerHTML = '<p>🔄 Loading map data...</p>';
    
    try {
        const response = await fetch('/api/map-data');
        const data = await response.json();
        
        if (data.attacks && data.attacks.length > 0) {
            // Hide placeholder, show map
            placeholder.style.display = 'none';
            mapElement.style.display = 'block';
            
            // Initialize or update map
            initMap(data.attacks);
        } else {
            placeholder.innerHTML = `
                <p>📍 No attack data available yet</p>
                <button onclick="window.honeypotDashboard.loadMapData()" class="btn-small">Refresh Map</button>
            `;
        }
    } catch (error) {
        console.error('Error loading map data:', error);
        placeholder.innerHTML = `
            <p>⚠️ Error loading map data</p>
            <button onclick="window.honeypotDashboard.loadMapData()" class="btn-small">Retry</button>
        `;
    }
}

function initMap(attacks) {
    console.log('🗺️ Initializing map with', attacks.length, 'locations');
    
    // Update counter
    document.getElementById('mapCount').textContent = `${attacks.length} locations`;
    
    // Filter attacks that have coordinates
    const validAttacks = attacks.filter(a => a.lat && a.lon);
    
    if (validAttacks.length === 0) {
        console.warn('No attacks with valid coordinates');
        return;
    }
    
    // Create map if it doesn't exist
    if (!attackMap) {
        attackMap = L.map('attackMap').setView([20, 0], 2);
        
        // Add tile layer (map background)
        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: '© OpenStreetMap contributors',
            maxZoom: 18
        }).addTo(attackMap);
    } else {
        // Clear existing markers
        attackMap.eachLayer(layer => {
            if (layer instanceof L.Marker) {
                attackMap.removeLayer(layer);
            }
        });
    }
    
    // Add markers for each attack
    validAttacks.forEach(attack => {
        const marker = L.marker([attack.lat, attack.lon]).addTo(attackMap);
        
        // Create popup content
        const popupContent = `
            <strong>IP:</strong> ${attack.ip}<br>
            <strong>Location:</strong> ${attack.city || 'Unknown'}, ${attack.country || 'Unknown'}<br>
            <strong>Attacks:</strong> ${attack.count}
        `;
        
        marker.bindPopup(popupContent);
    });
    
    console.log('✅ Map initialized with', validAttacks.length, 'markers');
}

// ============================================================================
// Map Auto-Refresh on New IP
// ============================================================================
let knownIPs = new Set();
let mapRefreshTimeout = null;

function refreshMapForNewIP(attack) {
    const ip = attack.source_ip;
    
    // Check if this is a new IP we haven't seen
    if (!knownIPs.has(ip)) {
        knownIPs.add(ip);
        console.log('🆕 New IP detected:', ip, '- Will refresh map');
        
        // Debounce map refresh (wait 2 seconds for multiple IPs)
        clearTimeout(mapRefreshTimeout);
        mapRefreshTimeout = setTimeout(() => {
            console.log('🔄 Refreshing map with new IPs...');
            loadMapData();
        }, 2000);
    }
}

// ============================================================================
// Export for debugging
// ============================================================================

window.honeypotDashboard = {
    loadStats,
    clearFeed,
    loadMapData,
    socket
};

console.log('💡 Debugging available via: window.honeypotDashboard');

// ============================================================================
// Filtering System
// ============================================================================

function setupFilters() {
    const filterIP = document.getElementById('filterIP');
    const filterPort = document.getElementById('filterPort');
    const filterEvent = document.getElementById('filterEvent');
    const filterTime = document.getElementById('filterTime');
    const clearBtn = document.getElementById('clearFilters');
    const exportCSV = document.getElementById('exportCSV');
    const exportPDF = document.getElementById('exportPDF');
    
    // Add event listeners
    filterIP.addEventListener('input', applyFilters);
    filterPort.addEventListener('change', applyFilters);
    filterEvent.addEventListener('change', applyFilters);
    filterTime.addEventListener('change', onTimeFilterChange);
    clearBtn.addEventListener('click', clearAllFilters);
    exportCSV.addEventListener('click', handleExportCSV);
    exportPDF.addEventListener('click', handleExportPDF);
}

function onTimeFilterChange() {
    activeFilters.time = document.getElementById('filterTime').value;
    
    // Update timeline label
    const labels = {
        'all': 'All Time',
        '12h': 'Last 12h',
        '24h': 'Last 24h',
        '7d': 'Last 7 Days',
        '30d': 'Last 30 Days'
    };
    document.getElementById('timelineLabel').textContent = labels[activeFilters.time] || 'Last 24h';
    
    // Reload data from backend with new time range
    loadStats();
}

function applyFilters() {
    // Get filter values
    activeFilters.ip = document.getElementById('filterIP').value.toLowerCase().trim();
    activeFilters.port = document.getElementById('filterPort').value;
    activeFilters.event = document.getElementById('filterEvent').value;
    
    // Filter feed items
    const feed = document.getElementById('liveFeed');
    const items = Array.from(feed.querySelectorAll('.feed-item'));
    
    items.forEach(item => {
        let show = true;
        const text = item.textContent.toLowerCase();
        
        // IP filter
        if (activeFilters.ip && !text.includes(activeFilters.ip)) {
            show = false;
        }
        
        // Port filter (check for SSH/Telnet/HTTP/FTP mentions)
        if (activeFilters.port) {
            const portMap = {
                '22': 'ssh',
                '23': 'telnet',
                '80': 'http',
                '21': 'ftp'
            };
            const serviceName = portMap[activeFilters.port];
            if (!text.includes(serviceName)) {
                show = false;
            }
        }
        
        // Event type filter
        if (activeFilters.event) {
            if (activeFilters.event === 'credential' && !item.classList.contains('credential')) {
                show = false;
            } else if (activeFilters.event === 'command' && !item.classList.contains('command')) {
                show = false;
            } else if (activeFilters.event === 'connection' && 
                      (item.classList.contains('credential') || item.classList.contains('command'))) {
                show = false;
            }
        }
        
        // Show or hide item
        item.style.display = show ? 'flex' : 'none';
    });
    
    console.log('🔍 Filters applied:', activeFilters);
}

function clearAllFilters() {
    document.getElementById('filterIP').value = '';
    document.getElementById('filterPort').value = '';
    document.getElementById('filterEvent').value = '';
    document.getElementById('filterTime').value = '24h';
    
    activeFilters = { ip: '', port: '', event: '', time: '24h' };
    
    // Reload data from backend
    loadStats();
    
    // Show all items in feed
    const feed = document.getElementById('liveFeed');
    const items = feed.querySelectorAll('.feed-item');
    items.forEach(item => item.style.display = 'flex');
    
    console.log('🔍 Filters cleared');
}

// ============================================================================
// Export Functions
// ============================================================================

function handleExportCSV() {
    // Build query string with current filters
    const params = new URLSearchParams();
    if (activeFilters.ip) params.append('ip', activeFilters.ip);
    if (activeFilters.port) params.append('port', activeFilters.port);
    if (activeFilters.event) params.append('event_type', activeFilters.event);
    if (activeFilters.time) params.append('time_range', activeFilters.time);
    
    // Trigger download
    const url = `/api/export/csv?${params.toString()}`;
    window.location.href = url;
    console.log('📥 Exporting CSV...');
}

function handleExportPDF() {
    // Build query string with current filters
    const params = new URLSearchParams();
    if (activeFilters.ip) params.append('ip', activeFilters.ip);
    if (activeFilters.port) params.append('port', activeFilters.port);
    if (activeFilters.event) params.append('event_type', activeFilters.event);
    if (activeFilters.time) params.append('time_range', activeFilters.time);
    
    // Trigger download
    const url = `/api/export/pdf?${params.toString()}`;
    window.location.href = url;
    console.log('📥 Exporting PDF...');
}
