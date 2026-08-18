class DashboardApp {
    constructor() {
        this.eventsTableBody = document.getElementById('events-body');
        this.lastEventTime = null;
        this.protocolChart = null;
        this.pollInterval = 5000;
        this.knownEventIds = new Set();
        this.maxEventsDisplay = 100;
        
        // Protocol colors mapping
        this.protoColors = {
            'HTTP': '#3b82f6',
            'SSH': '#10b981',
            'FTP': '#f59e0b',
            'SMTP': '#8b5cf6',
            'PROXY': '#64748b'
        };
    }

    init() {
        this.initCharts();
        this.updateTime();
        
        // Initial fetch
        this.fetchStats();
        this.fetchEvents();
        
        // Set intervals
        setInterval(() => this.updateTime(), 1000);
        setInterval(() => this.fetchStats(), this.pollInterval);
        setInterval(() => this.fetchEvents(), this.pollInterval);
    }

    updateTime() {
        const now = new Date();
        document.getElementById('current-time').textContent = now.toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
    }

    formatTimestamp(isoString) {
        if (!isoString) return 'Unknown';
        
        const date = new Date(isoString);
        const now = new Date();
        const diff = Math.floor((now - date) / 1000); // in seconds
        
        if (diff < 5) return 'just now';
        if (diff < 60) return `${diff}s ago`;
        if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
        if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
        
        return date.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
    }

    createProtocolBadge(protocol) {
        const p = (protocol || 'UNKNOWN').toUpperCase();
        let badgeClass = 'badge-proxy';
        
        if (p === 'HTTP') badgeClass = 'badge-http';
        else if (p === 'SSH') badgeClass = 'badge-ssh';
        else if (p === 'FTP') badgeClass = 'badge-ftp';
        else if (p === 'SMTP') badgeClass = 'badge-smtp';
        
        return `<span class="badge ${badgeClass}">${p}</span>`;
    }

    initCharts() {
        const ctx = document.getElementById('protocol-chart').getContext('2d');
        Chart.defaults.color = '#94a3b8';
        Chart.defaults.font.family = 'Inter, sans-serif';
        
        this.protocolChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: [],
                    borderWidth: 0,
                    hoverOffset: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: {
                            padding: 20,
                            boxWidth: 12
                        }
                    },
                    tooltip: {
                        backgroundColor: 'rgba(18, 18, 26, 0.9)',
                        titleColor: '#e2e8f0',
                        bodyColor: '#e2e8f0',
                        borderColor: '#27273a',
                        borderWidth: 1,
                        padding: 10
                    }
                },
                cutout: '70%'
            }
        });
    }

    async fetchEvents() {
        try {
            const response = await fetch('/api/events?limit=50');
            if (!response.ok) throw new Error('Network response was not ok');
            const events = await response.json();
            this.updateEventFeed(events);
            this.updateCredentials(events);
            this.updateStatus('Auto-updating...', 'online');
        } catch (error) {
            console.error('Failed to fetch events:', error);
            this.updateStatus('Reconnecting...', 'offline');
        }
    }

    async fetchStats() {
        try {
            const response = await fetch('/api/stats');
            if (!response.ok) throw new Error('Network response was not ok');
            const stats = await response.json();
            this.updateStatCards(stats);
            this.updateCharts(stats);
            this.updateTopAttackers(stats);
        } catch (error) {
            console.error('Failed to fetch stats:', error);
        }
    }
    
    updateStatus(msg, state) {
        const el = document.getElementById('refresh-status');
        el.textContent = msg;
        if (state === 'offline') {
            el.style.color = 'var(--accent-critical)';
        } else {
            el.style.color = 'var(--text-muted)';
        }
    }

    updateStatCards(stats) {
        // Calculate total events
        const total = Object.values(stats.event_types || {}).reduce((a, b) => a + b, 0);
        document.getElementById('stat-total-events').textContent = total.toLocaleString();
        
        // Active attackers count
        const activeAttackers = Object.keys(stats.top_ips || {}).length;
        document.getElementById('stat-active-attackers').textContent = activeAttackers.toLocaleString();
        
        // Proxy requests (assuming event type 'PROXY_REQUEST')
        const proxyReqs = (stats.event_types || {})['PROXY_REQUEST'] || 0;
        document.getElementById('stat-proxy-requests').textContent = proxyReqs.toLocaleString();
        
        // Alerts
        const alerts = (stats.event_types || {})['ALERT'] || 0;
        document.getElementById('stat-alerts').textContent = alerts.toLocaleString();
    }

    updateCharts(stats) {
        const protocols = stats.protocols || {};
        const labels = Object.keys(protocols);
        const data = Object.values(protocols);
        const colors = labels.map(l => this.protoColors[l.toUpperCase()] || this.protoColors['PROXY']);
        
        this.protocolChart.data.labels = labels;
        this.protocolChart.data.datasets[0].data = data;
        this.protocolChart.data.datasets[0].backgroundColor = colors;
        this.protocolChart.update();
    }

    updateTopAttackers(stats) {
        const list = document.getElementById('attacker-list');
        const topIps = stats.top_ips || {};
        
        // Find max for bar scaling
        const maxCount = Math.max(...Object.values(topIps), 1);
        
        list.innerHTML = '';
        
        for (const [ip, count] of Object.entries(topIps)) {
            const width = Math.max(5, (count / maxCount) * 100);
            
            const li = document.createElement('li');
            li.className = 'attacker-item';
            li.innerHTML = `
                <span class="attacker-ip">${ip}</span>
                <div class="attacker-bar-container">
                    <div class="attacker-bar" style="width: ${width}%"></div>
                </div>
                <span class="attacker-count">${count}</span>
            `;
            list.appendChild(li);
        }
        
        if (Object.keys(topIps).length === 0) {
            list.innerHTML = '<li style="color: var(--text-muted); font-size: 0.85rem;">No attackers recorded yet.</li>';
        }
    }

    updateCredentials(events) {
        const list = document.getElementById('credentials-list');
        
        // Filter for login attempts
        const loginEvents = events.filter(e => 
            e.event_type === 'LOGIN_ATTEMPT' && 
            e.username
        ).slice(0, 5); // Take top 5
        
        if (loginEvents.length === 0) {
            if (list.children.length === 0) {
                list.innerHTML = '<div style="color: var(--text-muted); font-size: 0.85rem; padding: 0.75rem;">No credentials captured yet.</div>';
            }
            return;
        }
        
        list.innerHTML = '';
        loginEvents.forEach(e => {
            const div = document.createElement('div');
            div.className = 'credential-item';
            
            const proto = e.protocol ? `[${e.protocol}]` : '';
            const pwDisplay = e.password ? e.password : '<i>none</i>';
            
            div.innerHTML = `
                <div><strong>${proto} ${e.src_ip || 'Unknown'}</strong></div>
                <div>User: <span style="color: var(--text-main)">${e.username}</span></div>
                <div>Pass: <span style="color: var(--accent-secondary)">${pwDisplay}</span></div>
            `;
            list.appendChild(div);
        });
    }

    updateEventFeed(events) {
        // We assume events are returned newest first
        if (!events || events.length === 0) return;
        
        // Find events we haven't seen yet
        // In a real app we'd use proper IDs, using timestamp+IP as a crude ID here
        const newEvents = [];
        
        for (const event of events) {
            // Create a unique-ish ID
            const eventId = `${event.timestamp}-${event.src_ip}-${event.event_type}`;
            if (!this.knownEventIds.has(eventId)) {
                newEvents.push(event);
                this.knownEventIds.add(eventId);
                
                // Keep set size manageable
                if (this.knownEventIds.size > 1000) {
                    const toDelete = Array.from(this.knownEventIds).slice(0, 100);
                    toDelete.forEach(id => this.knownEventIds.delete(id));
                }
            }
        }
        
        // If it's the first load, don't animate all of them
        const isFirstLoad = this.eventsTableBody.children.length === 0;
        
        // Process in reverse to add oldest first (among the new ones) to the top
        for (let i = newEvents.length - 1; i >= 0; i--) {
            const event = newEvents[i];
            const row = document.createElement('tr');
            
            if (!isFirstLoad) {
                row.className = 'new-row';
            }
            
            // Build details string
            let details = event.message || '';
            if (event.url) details = event.url;
            else if (event.command) details = `CMD: ${event.command}`;
            
            // Truncate long details
            if (details.length > 50) details = details.substring(0, 47) + '...';
            
            row.innerHTML = `
                <td class="cell-time" title="${event.timestamp}">${this.formatTimestamp(event.timestamp)}</td>
                <td>${this.createProtocolBadge(event.protocol)}</td>
                <td class="cell-ip">${event.src_ip || '-'}</td>
                <td>${event.event_type || '-'}</td>
                <td title="${event.message || ''}">${details}</td>
            `;
            
            this.eventsTableBody.insertBefore(row, this.eventsTableBody.firstChild);
        }
        
        // Trim old events
        while (this.eventsTableBody.children.length > this.maxEventsDisplay) {
            this.eventsTableBody.removeChild(this.eventsTableBody.lastChild);
        }
        
        // Update relative times for existing rows
        const rows = this.eventsTableBody.querySelectorAll('tr');
        rows.forEach(row => {
            const timeCell = row.querySelector('.cell-time');
            if (timeCell && timeCell.title) {
                timeCell.textContent = this.formatTimestamp(timeCell.title);
            }
        });
    }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    const app = new DashboardApp();
    app.init();
});
