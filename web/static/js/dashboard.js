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
    time: 'all' // Default to all time (show all enriched attacks)
};

// ============================================================================
// Initialization
// ============================================================================

document.addEventListener('DOMContentLoaded', function() {
    console.log('[LOG] Dashboard event');
    
    // Initialize WebSocket connection
    initWebSocket();
    
    // Load initial data
    loadStats();
    loadMLMetrics();
    
    // Set up auto-refresh every 5 seconds (stats + map together)
    setInterval(() => {
        loadStats();
        loadMapData();
    }, 5000);
    
    // Refresh ML metrics every 10 seconds
    setInterval(loadMLMetrics, 10000);
    
    // Initialize charts
    initCharts();
    loadMapData();
    
    // Setup filter listeners
    setupFilters();
    
    console.log('[LOG] Dashboard event');
});

// ============================================================================
// WebSocket Connection
// ============================================================================

function initWebSocket() {
    socket = io();
    
    socket.on('connect', function() {
        console.log('[LOG] Dashboard event');
        updateConnectionStatus(true);
    });
    
    socket.on('disconnect', function() {
        console.log('[LOG] Dashboard event');
        updateConnectionStatus(false);
    });
    
    socket.on('connected', function(data) {
        console.log('Server says:', data);
    });
    
    socket.on('stats_update', function(stats) {
        console.log('[STATS] Update received:', stats);
        updateDashboard(stats);
    });
    
    socket.on('new_attack', function(attack) {
        console.log('[ATTACK] New attack:', attack);
        addToLiveFeed(attack);
        
        // Refresh stats immediately
        loadStats();
        
        // Immediately refresh map (no delay)
        console.log('[MAP] Refreshing for new attack');
        setTimeout(() => loadMapData(), 500);
    });
}

function updateConnectionStatus(connected) {
    const statusEl = document.getElementById('connectionStatus');
    if (connected) {
        statusEl.innerHTML = '<span class="dot"></span> LIVE';
        statusEl.classList.add('connected');
        statusEl.classList.remove('disconnected');
    } else {
        statusEl.innerHTML = '<span class="dot"></span> OFFLINE';
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
    updateStatIfChanged('credsCaptured', stats.credentials_captured || 0);
    updateStatIfChanged('avgThreat', stats.avg_threat_score || 0);
    updateStatIfChanged('active24h', stats.active_ips_24h || 0);
    
    // Update uptime in header
    if (stats.uptime) {
        document.getElementById('systemUptime').textContent = stats.uptime;
    }
    
    // Update top IPs
    updateTopIPs(stats.top_ips || []);
    
    // Update threat intelligence
    updateThreatIntelligence(stats.threat_ips || []);
    
    // Update port chart
    updatePortChart(stats.ports || {});
    
    // Update timeline chart
    updateTimelineChart(stats.recent_events || []);
    
    // Update recent events in feed
    if (stats.recent_events && stats.recent_events.length > 0) {
        updateLiveFeed(stats.recent_events);
    }
    
    // Update timestamp
    updateTimestamp();
}

// Load ML metrics and update dashboard
function loadMLMetrics() {
    fetch('/api/ml-metrics')
        .then(res => res.json())
        .then(data => {
            updateMLMetrics(data);
        })
        .catch(err => {
            console.log('⚠ ML metrics not available:', err);
        });
}

// Update ML metrics in dashboard
function updateMLMetrics(data) {
    // Update model performance
    const baselineAccuracyEl = document.getElementById('baselineAccuracy');
    const enhancedAccuracyEl = document.getElementById('enhancedAccuracy');
    const improvementEl = document.getElementById('mlImprovement');
    
    if (baselineAccuracyEl) baselineAccuracyEl.textContent = 
        (data.baseline_accuracy * 100).toFixed(2) + '%';
    if (enhancedAccuracyEl) enhancedAccuracyEl.textContent = 
        (data.enhanced_accuracy * 100).toFixed(2) + '%';
    if (improvementEl) improvementEl.textContent = 
        (data.improvement * 100).toFixed(2) + '%';
    
    // Update classification stats
    const botCountEl = document.getElementById('botCount');
    const botPercentEl = document.getElementById('botPercent');
    const humanCountEl = document.getElementById('humanCount');
    const humanPercentEl = document.getElementById('humanPercent');
    
    if (botCountEl) botCountEl.textContent = data.bot_count || 0;
    if (botPercentEl) botPercentEl.textContent = 
        (data.bot_percent * 100).toFixed(1) + '%';
    if (humanCountEl) humanCountEl.textContent = data.human_count || 0;
    if (humanPercentEl) humanPercentEl.textContent = 
        (data.human_percent * 100).toFixed(1) + '%';
    
    // Update feature importance
    if (data.feature_importance) {
        updateFeatureImportance(data.feature_importance);
    }
}

// Update feature importance bars
function updateFeatureImportance(features) {
    const container = document.getElementById('featureImportance');
    if (!container) return;
    
    container.innerHTML = '';
    
    // Sort features by importance descending
    const sorted = Object.entries(features)
        .sort((a, b) => b[1] - a[1]);
    
    sorted.forEach(([name, importance]) => {
        const pct = (importance * 100).toFixed(1);
        const html = `
            <div class="feature-bar">
                <div class="feature-name">${name}</div>
                <div class="bar-container">
                    <div class="bar-fill" style="width: ${pct}%">
                        <div class="bar-label">${pct}%</div>
                    </div>
                </div>
            </div>
        `;
        container.innerHTML += html;
    });
}

// Helper to only update and animate when value changes
function updateStatIfChanged(id, newValue) {
    const element = document.getElementById(id);
    if (!element) return;
    
    // Handle different formats (number or string with suffix)
    let currentValue = 0;
    if (id === 'avgThreat') {
        currentValue = parseInt(element.textContent) || 0;
    } else {
        currentValue = parseInt(element.textContent) || 0;
    }
    
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
        const displayValue = Math.floor(current);
        // Add percentage for threat score
        if (id === 'avgThreat') {
            element.textContent = displayValue + '%';
        } else {
            element.textContent = displayValue;
        }
    }, 16);
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
// Threat Intelligence
// ============================================================================

function updateThreatIntelligence(threatIPs) {
    const container = document.getElementById('threatIntel');
    
    if (!threatIPs || threatIPs.length === 0) {
        container.innerHTML = `
            <div class="threat-item">
                <span class="threat-placeholder">No threats detected</span>
            </div>
        `;
        return;
    }
    
    container.innerHTML = threatIPs.slice(0, 10).map((item, index) => {
        let riskClass = 'safe';
        let riskLabel = 'SAFE';
        const score = item.abuse_score || 0;
        
        if (score >= 75) {
            riskClass = 'critical';
            riskLabel = 'CRITICAL';
        } else if (score >= 25) {
            riskClass = 'warning';
            riskLabel = 'WARNING';
        }
        
        const torTag = item.is_tor ? `<span class="threat-tag tor">TOR</span>` : '';
        const countryTag = item.country ? `<span class="threat-tag country">${item.country}</span>` : '';
        const reportsTag = `<span class="threat-tag reports">${item.total_reports} reports</span>`;
        
        let detailsHTML = '';
        if (item.isp || item.num_distinct_users || item.usage_type) {
            detailsHTML = `<div class="threat-details">
                ${item.isp ? `<div class="threat-detail-row"><span class="threat-detail-label">ISP:</span><span class="threat-detail-value">${item.isp}</span></div>` : ''}
                ${item.num_distinct_users ? `<div class="threat-detail-row"><span class="threat-detail-label">Users:</span><span class="threat-detail-value">${item.num_distinct_users}</span></div>` : ''}
                ${item.usage_type ? `<div class="threat-detail-row"><span class="threat-detail-label">Type:</span><span class="threat-detail-value">${item.usage_type}</span></div>` : ''}
            </div>`;
        }
        
        return `
            <div class="threat-item threat-${riskClass}" style="--delay: ${index}">
                <div class="threat-header">
                    <span class="threat-ip">${item.ip}</span>
                    <span class="threat-score ${riskClass}">${score}%</span>
                </div>
                <div class="threat-tags">
                    ${torTag}
                    ${countryTag}
                    ${reportsTag}
                </div>
                ${detailsHTML}
            </div>
        `;
    }).join('');
}

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
        
        // Get threat intelligence data
        const threat = event.threat_intelligence || {};
        const threatData = threat.threat_data || {};
        const abuseScore = threatData.abuseConfidenceScore || 0;
        
        // Determine risk level
        let riskLevel = 'low';
        let riskLabel = 'SAFE';
        if (abuseScore >= 75) {
            riskLevel = 'high';
            riskLabel = 'CRITICAL';
        } else if (abuseScore >= 25) {
            riskLevel = 'medium';
            riskLabel = 'WARNING';
        }
        
        // Determine event type label
        let eventType = 'CONNECTION';
        if (isCredential) {
            eventType = 'CREDENTIALS_CAPTURED';
        } else if (isCommand) {
            eventType = 'COMMAND_EXECUTION';
        } else if (event.event_type) {
            eventType = event.event_type.replace(/_/g, '_');
        }
        
        const feedItem = document.createElement('div');
        feedItem.className = `attack-item ${riskLevel}`;
        feedItem.dataset.timestamp = event.timestamp;
        feedItem.innerHTML = `
            <div class="attack-header">
                <div class="attack-type">${eventType}</div>
                <div class="risk-badge ${riskLevel}">${riskLabel}</div>
            </div>
            <div class="attack-ip">${event.source_ip}<span class="attack-arrow">→</span>${event.service?.toUpperCase()}<span class="attack-arrow">:</span>${event.port || '?'}</div>
            <div class="attack-timestamp">${time}</div>
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
    const time = new Date(attack.timestamp || new Date()).toLocaleTimeString('en-US', {hour12: false});
    
    // Remove placeholder if it exists
    const placeholder = feed.querySelector('.feed-placeholder');
    if (placeholder) {
        placeholder.remove();
    }
    
    const isCredential = attack.credentials || attack.event_type === 'CREDENTIAL_SUBMISSION' || attack.event_type === 'SSH_LOGIN';
    const isCommand = attack.event_type?.startsWith('CMD:');
    
    // Determine event type label
    let eventType = 'CONNECTION';
    if (isCredential) {
        eventType = 'CREDENTIALS_CAPTURED';
    } else if (isCommand) {
        eventType = 'COMMAND_EXECUTION';
    } else if (attack.event_type) {
        eventType = attack.event_type.replace(/_/g, '_');
    }
    
    // Get threat intelligence data
    const threat = attack.threat_intelligence || {};
    const threatData = threat.threat_data || {};
    const abuseScore = threatData.abuseConfidenceScore || 0;
    const totalReports = threatData.totalReports || 0;
    const isTor = threatData.isTor || false;
    
    // Determine risk level
    let riskLevel = 'low';
    let riskLabel = 'SAFE';
    if (abuseScore >= 75) {
        riskLevel = 'high';
        riskLabel = 'CRITICAL';
    } else if (abuseScore >= 25) {
        riskLevel = 'medium';
        riskLabel = 'WARNING';
    }
    
    // Build details string
    let details = [];
    if (attack.credentials) {
        details.push(`AUTH: ${attack.credentials}`);
    } else if (isCommand) {
        const command = attack.event_type.replace('CMD: ', '');
        details.push(`CMD: ${command}`);
    }
    
    if (threat.status === 'success') {
        if (isTor) details.push('TOR_EXIT');
        details.push(`SCORE: ${abuseScore}%`);
        if (totalReports > 0) details.push(`REPORTS: ${totalReports}`);
        if (threatData.isWhitelisted) details.push('WHITELISTED');
    }
    
    const detailsStr = details.join('<span class="detail-separator">|</span>');
    
    const feedItem = document.createElement('div');
    feedItem.className = `attack-item ${riskLevel}`;
    feedItem.dataset.timestamp = attack.timestamp || new Date().toISOString();
    feedItem.innerHTML = `
        <div class="attack-header">
            <div class="attack-type">${eventType}</div>
            <div class="risk-badge ${riskLevel}">${riskLabel}</div>
        </div>
        <div class="attack-ip">${attack.source_ip}<span class="attack-arrow">→</span>${attack.service?.toUpperCase()}<span class="attack-arrow">:</span>${attack.port || '?'}</div>
        ${detailsStr ? `<div class="attack-details">${detailsStr}</div>` : ''}
        <div class="attack-timestamp">${time}</div>
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
    console.log('[MAP] loadMapData() called');
    const placeholder = document.getElementById('mapPlaceholder');
    const mapElement = document.getElementById('attackMap');
    
    console.log('[MAP] Elements found:', {placeholder: !!placeholder, mapElement: !!mapElement});
    
    try {
        console.log('[MAP] Fetching /api/map-data...');
        const response = await fetch('/api/map-data');
        const data = await response.json();
        console.log('[MAP] Received data:', data);
        
        // Always show map, hide placeholder
        placeholder.style.display = 'none';
        mapElement.style.display = 'block';
        
        // Initialize map (will show empty if no attacks)
        setTimeout(() => {
            initMap(data.attacks || []);
        }, 50);
        
    } catch (error) {
        console.error('[MAP ERROR] Failed to load map data:', error);
        // Still show empty map on error
        placeholder.style.display = 'none';
        mapElement.style.display = 'block';
        setTimeout(() => {
            initMap([]);
        }, 50);
    }
}

function initMap(attacks) {
    console.log('🗺️ Initializing map with', attacks.length, 'locations');
    
    // Update counter
    document.getElementById('mapCount').textContent = `${attacks.length} LOCATIONS`;
    
    // Filter attacks that have coordinates
    const validAttacks = attacks.filter(a => a.lat && a.lon);
    
    // Check if Leaflet is loaded
    if (typeof L === 'undefined') {
        console.error('[ERROR] Leaflet not loaded');
        return;
    }
    
    // Create map if it doesn't exist
    if (!attackMap) {
        try {
            const mapElement = document.getElementById('attackMap');
            if (!mapElement) {
                console.error('[ERROR] Map element not found');
                return;
            }
            
            attackMap = L.map('attackMap', {
                center: [20, 0],
                zoom: 2,
                minZoom: 2,
                maxZoom: 18,
                worldCopyJump: true,
                zoomControl: true,
                maxBounds: [[-90, -Infinity], [90, Infinity]], // Limit only vertical panning
                maxBoundsViscosity: 1.0 // Make bounds "hard"
            });
            
            // Use dark tile layer that matches our theme
            L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
                attribution: '© OpenStreetMap, © CARTO',
                maxZoom: 18,
                minZoom: 2,
                noWrap: false
            }).addTo(attackMap);
            
            // Force map to recognize container dimensions
            setTimeout(() => {
                attackMap.invalidateSize();
                console.log('[MAP] Initialized');
            }, 100);
        } catch (error) {
            console.error('[ERROR] Map initialization failed:', error);
            return;
        }
    } else {
        // Clear existing markers
        try {
            attackMap.eachLayer(layer => {
                if (layer instanceof L.Marker) {
                    attackMap.removeLayer(layer);
                }
            });
        } catch (error) {
            console.error('[MAP] Error clearing markers:', error);
        }
    }
    
    // Add markers for each attack (with error handling)
    validAttacks.forEach(attack => {
        try {
            const marker = L.marker([attack.lat, attack.lon]).addTo(attackMap);
            
            // Create popup content
            const popupContent = `
                <strong>IP:</strong> ${attack.ip}<br>
                <strong>Location:</strong> ${attack.city || 'Unknown'}, ${attack.country || 'Unknown'}<br>
                <strong>Attacks:</strong> ${attack.count}
            `;
            
            marker.bindPopup(popupContent);
        } catch (error) {
            console.error('[MAP] Error adding marker for', attack.ip, error);
        }
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
            console.log('[LOG] Dashboard event');
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

console.log('[LOG] Dashboard event');

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
    const clearDataBtn = document.getElementById('clearData');
    
    // Add event listeners
    filterIP.addEventListener('input', applyFilters);
    filterPort.addEventListener('change', applyFilters);
    filterEvent.addEventListener('change', applyFilters);
    filterTime.addEventListener('change', onTimeFilterChange);
    clearBtn.addEventListener('click', clearAllFilters);
    exportCSV.addEventListener('click', handleExportCSV);
    exportPDF.addEventListener('click', handleExportPDF);
    if (clearDataBtn) clearDataBtn.addEventListener('click', handleClearData);
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
    
    // Reload stats and map from backend with filters applied
    loadStats();
    loadMapData();
    
    // Also filter feed items for immediate visual feedback
    const feed = document.getElementById('liveFeed');
    const items = Array.from(feed.querySelectorAll('.attack-item'));
    
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
    document.getElementById('filterTime').value = 'all';
    
    activeFilters = { ip: '', port: '', event: '', time: 'all' };
    loadStats();
    loadMapData();
    console.log('Filters cleared');
}

function handleClearData() {
    console.log('[DEBUG] Clear data button clicked');
    
    // Show custom modal
    const modal = document.getElementById('clearDataModal');
    const input = document.getElementById('deleteConfirmInput');
    const confirmBtn = document.getElementById('confirmDelete');
    const cancelBtn = document.getElementById('cancelDelete');
    
    modal.style.display = 'flex';
    input.value = '';
    confirmBtn.disabled = true;
    
    // Enable confirm button only when "DELETE" is typed
    const checkInput = () => {
        confirmBtn.disabled = input.value !== 'DELETE';
    };
    
    input.addEventListener('input', checkInput);
    input.focus();
    
    // Handle cancel
    const closeModal = () => {
        modal.style.display = 'none';
        input.removeEventListener('input', checkInput);
    };
    
    cancelBtn.onclick = () => {
        console.log('[DEBUG] Clear data cancelled by user');
        closeModal();
    };
    
    // Handle confirm
    confirmBtn.onclick = () => {
        console.log('[DEBUG] Confirmation passed, calling API...');
        closeModal();
        
        fetch('/api/clear-data', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        })
        .then(response => response.json())
        .then(data => {
            console.log('[DEBUG] API response:', data);
            if (data.success) {
                // Show success message with custom alert
                const successDiv = document.createElement('div');
                successDiv.style.cssText = 'position: fixed; top: 20px; right: 20px; background: #4caf50; color: white; padding: 20px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.3); z-index: 10001; font-weight: 600;';
                successDiv.textContent = `Deleted ${data.deleted} file(s) successfully`;
                document.body.appendChild(successDiv);
                
                setTimeout(() => location.reload(), 1500);
            } else {
                alert('Error: ' + data.message);
            }
        })
        .catch(error => {
            console.error('[DEBUG] Error clearing data:', error);
            alert('Failed to clear data: ' + error);
        });
    };
    
    // Close on Escape key
    const escapeHandler = (e) => {
        if (e.key === 'Escape') {
            closeModal();
            document.removeEventListener('keydown', escapeHandler);
        }
    };
    document.addEventListener('keydown', escapeHandler);
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
    console.log('[LOG] Dashboard event');
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
    console.log('[LOG] Dashboard event');
}
