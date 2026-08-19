/**
 * ShadowGate Dashboard — Real-time monitoring frontend.
 * v1.1.0
 */

class DashboardApp {
    constructor() {
        this.pollInterval = 5000;
        this.chart = null;
        this.lastEventCount = 0;
        this.isConnected = true;
    }

    init() {
        this.initChart();
        this.fetchStats();
        this.fetchEvents();
        this.fetchCredentials();
        setInterval(() => this.fetchStats(), this.pollInterval);
        setInterval(() => this.fetchEvents(), this.pollInterval);
        setInterval(() => this.fetchCredentials(), this.pollInterval * 2);

        // Export buttons
        document.getElementById('export-json')?.addEventListener('click', () => {
            window.location.href = '/api/export/json';
        });
        document.getElementById('export-csv')?.addEventListener('click', () => {
            window.location.href = '/api/export/csv';
        });
    }

    initChart() {
        const ctx = document.getElementById('protocolChart');
        if (!ctx) return;
        this.chart = new Chart(ctx.getContext('2d'), {
            type: 'doughnut',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: ['#3b82f6', '#10b981', '#f59e0b', '#8b5cf6', '#6b7280', '#ef4444'],
                    borderWidth: 0,
                    hoverOffset: 6,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '65%',
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: '#a1a1aa', padding: 16, font: { size: 12, family: 'Inter' } },
                    },
                },
            },
        });
    }

    async fetchStats() {
        try {
            const res = await fetch('/api/stats');
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const stats = await res.json();
            this.updateStatCards(stats);
            this.updateChart(stats);
            this.updateTopAttackers(stats);
            this.setConnected(true);
        } catch (e) {
            console.error('Stats fetch error:', e);
            this.setConnected(false);
        }
    }

    async fetchEvents() {
        try {
            const res = await fetch('/api/events?limit=50');
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const events = await res.json();
            this.updateEventFeed(events);
            this.setConnected(true);
        } catch (e) {
            console.error('Events fetch error:', e);
            this.setConnected(false);
        }
    }

    async fetchCredentials() {
        try {
            const res = await fetch('/api/credentials?limit=20');
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const creds = await res.json();
            this.updateCredentials(creds);
        } catch (e) {
            console.error('Credentials fetch error:', e);
        }
    }

    updateStatCards(stats) {
        const el = (id) => document.getElementById(id);
        if (el('stat-total')) el('stat-total').textContent = this.formatNumber(stats.total_events || 0);
        if (el('stat-attackers')) el('stat-attackers').textContent = this.formatNumber(stats.unique_ips || 0);
        if (el('stat-buffer')) el('stat-buffer').textContent = this.formatNumber(stats.events_in_buffer || 0);
        if (el('stat-credentials')) el('stat-credentials').textContent = this.formatNumber(stats.credentials_captured || 0);
    }

    updateChart(stats) {
        if (!this.chart) return;
        const protocols = stats.protocols || {};
        this.chart.data.labels = Object.keys(protocols).map(p => p.toUpperCase());
        this.chart.data.datasets[0].data = Object.values(protocols);
        this.chart.update('none');
    }

    updateEventFeed(events) {
        const feed = document.getElementById('event-feed');
        if (!feed) return;

        const newCount = events.length;
        const hasNew = newCount !== this.lastEventCount;
        this.lastEventCount = newCount;

        const rows = events.map((evt, i) => {
            const proto = (evt.protocol || 'unknown').toUpperCase();
            const badge = this.createProtocolBadge(proto);
            const time = this.formatTimestamp(evt.timestamp);
            const ip = evt.source_ip || evt.src_ip || 'N/A';
            const type = evt.event_type || '';
            const detail = this.getEventDetail(evt);
            const animClass = hasNew && i < 3 ? 'event-row-new' : '';

            return `<tr class="event-row ${animClass}">
                <td class="time-cell">${time}</td>
                <td>${badge}</td>
                <td class="ip-cell">${this.escapeHtml(ip)}</td>
                <td>${this.escapeHtml(type)}</td>
                <td class="detail-cell">${this.escapeHtml(detail)}</td>
            </tr>`;
        }).join('');

        feed.innerHTML = rows || '<tr><td colspan="5" class="empty-state">Waiting for events...</td></tr>';
    }

    updateTopAttackers(stats) {
        const container = document.getElementById('top-attackers');
        if (!container) return;
        const topIps = stats.top_ips || {};
        const entries = Object.entries(topIps);
        if (!entries.length) {
            container.innerHTML = '<div class="empty-state">No attackers detected</div>';
            return;
        }
        const maxCount = Math.max(...entries.map(([, c]) => c));
        container.innerHTML = entries.slice(0, 10).map(([ip, count]) => {
            const pct = Math.max(5, (count / maxCount) * 100);
            return `<div class="attacker-row">
                <span class="attacker-ip">${this.escapeHtml(ip)}</span>
                <div class="attacker-bar-bg"><div class="attacker-bar" style="width:${pct}%"></div></div>
                <span class="attacker-count">${count}</span>
            </div>`;
        }).join('');
    }

    updateCredentials(creds) {
        const container = document.getElementById('recent-creds');
        if (!container) return;
        if (!creds.length) {
            container.innerHTML = '<div class="empty-state">No credentials captured</div>';
            return;
        }
        container.innerHTML = creds.slice(0, 15).map(cred => {
            const proto = (cred.protocol || '').toUpperCase();
            const badge = this.createProtocolBadge(proto);
            return `<div class="cred-row">
                <span class="cred-time">${this.formatTimestamp(cred.timestamp)}</span>
                ${badge}
                <span class="cred-user">${this.escapeHtml(cred.username || '-')}</span>
                <span class="cred-sep">:</span>
                <span class="cred-pass">${this.escapeHtml(cred.password || '-')}</span>
                <span class="cred-ip">${this.escapeHtml(cred.source_ip || '')}</span>
            </div>`;
        }).join('');
    }

    // --- Helpers ---

    createProtocolBadge(proto) {
        const colors = {
            HTTP: '#3b82f6', SSH: '#10b981', FTP: '#f59e0b',
            SMTP: '#8b5cf6', PROXY: '#6b7280', TELNET: '#ec4899',
            UNKNOWN: '#52525b',
        };
        const color = colors[proto] || colors.UNKNOWN;
        return `<span class="protocol-badge" style="--badge-color:${color}">${proto}</span>`;
    }

    getEventDetail(evt) {
        if (evt.command) return evt.command;
        if (evt.username) return `user: ${evt.username}`;
        if (evt.path) return `${evt.method || 'GET'} ${evt.path}`;
        if (evt.url) return evt.url;
        if (evt.target) return evt.target;
        return '';
    }

    formatTimestamp(ts) {
        if (!ts) return '-';
        const date = new Date(ts);
        if (isNaN(date.getTime())) return ts;
        const now = Date.now();
        const diff = Math.floor((now - date.getTime()) / 1000);
        if (diff < 5) return 'just now';
        if (diff < 60) return `${diff}s ago`;
        if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
        if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
        return `${Math.floor(diff / 86400)}d ago`;
    }

    formatNumber(n) {
        if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M';
        if (n >= 1_000) return (n / 1_000).toFixed(1) + 'K';
        return n.toString();
    }

    escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    setConnected(connected) {
        const dot = document.getElementById('status-dot');
        const text = document.getElementById('status-text');
        if (dot) dot.className = connected ? 'status-dot online' : 'status-dot offline';
        if (text) text.textContent = connected ? 'Connected' : 'Reconnecting...';
        this.isConnected = connected;
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const app = new DashboardApp();
    app.init();
});
