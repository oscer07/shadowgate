<p align="center">
  <h1 align="center">🛡️ ShadowGate</h1>
  <p align="center"><strong>Private Proxy Server & Honeypot Toolkit</strong></p>
  <p align="center">v1.1.0 &bull; Open Source &bull; Self-Hosted</p>
  <p align="center">
    <a href="#features">Features</a> &bull;
    <a href="#quick-start">Quick Start</a> &bull;
    <a href="#configuration">Configuration</a> &bull;
    <a href="#deployment">Deployment</a> &bull;
    <a href="#contributing">Contributing</a>
  </p>
</p>

---

## Overview

ShadowGate is a self-hosted cybersecurity toolkit combining a **private authenticated proxy server** with a **multi-protocol honeypot system**. Built for security researchers, SOC teams, and network administrators.

## Features

### 🔒 Private Proxy Server
- HTTP/HTTPS forward proxy with CONNECT tunneling
- Basic Auth + API key authentication
- Token-bucket rate limiting (async-safe)
- IP whitelist/blacklist with CIDR support
- Domain filtering & bandwidth tracking
- Upstream proxy chaining (SOCKS5/HTTP)

### 🍯 Multi-Protocol Honeypot
- **HTTP** — WordPress, phpMyAdmin, Joomla, Drupal, admin panels, .env decoys, fake APIs
- **SSH** — Interactive shell with 20+ commands, session recording
- **FTP** — Credential capture, fake directory listings
- **SMTP** — Spam relay detection, full email capture
- **Telnet** — BusyBox/IoT device emulation *(new in v1.1.0)*
- Attacker fingerprinting with GeoIP & scanner detection

### 📊 Real-Time Dashboard
- Dark-theme SOC monitoring UI
- Live event feed with protocol badges
- Protocol distribution chart
- Top attackers ranking
- Captured credentials viewer
- CSV/JSON event export
- Optional login authentication

### 🚨 Alert System
- Slack, Discord, Email notifications
- Custom webhook message templates
- Cooldown deduplication

## Quick Start

```bash
# Clone and install
git clone https://github.com/YOUR_USERNAME/shadowgate.git
cd shadowgate
pip install -e .

# Run everything
shadowgate all

# Or individual components
shadowgate proxy --port 8080
shadowgate honeypot --protocols http,ssh,telnet
shadowgate dashboard --port 9090
```

### Docker

```bash
cp .env.example .env
docker-compose up -d
```

## Default Ports

| Service | Port |
|---------|------|
| Proxy | 8080 |
| HTTP Honeypot | 8443 |
| SSH Honeypot | 2222 |
| FTP Honeypot | 2121 |
| SMTP Honeypot | 2525 |
| Telnet Honeypot | 2323 |
| Dashboard | 9090 |

## Configuration

ShadowGate uses YAML configuration with environment variable overrides.

```bash
# Override any setting with SHADOWGATE_ prefix
export SHADOWGATE_PROXY__PORT=9090
export SHADOWGATE_HONEYPOT__SSH__PORT=22222
```

See `config/default.yaml` for all options.

## Architecture

```
shadowgate/
├── proxy/        # Private forward proxy
├── honeypot/     # Multi-protocol honeypots (HTTP, SSH, FTP, SMTP, Telnet)
├── dashboard/    # Flask web UI + REST API
├── logging/      # Structured JSON logging + alerts
└── config.py     # YAML + env var configuration
```

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/events` | List events (filterable by protocol, type) |
| `GET /api/stats` | Aggregate statistics |
| `GET /api/top-attackers` | Top attacker IPs |
| `GET /api/credentials` | Captured credentials |
| `GET /api/export/json` | Export events as JSON |
| `GET /api/export/csv` | Export events as CSV |
| `GET /api/health` | Health check |

## ⚠️ Legal Notice

Deploy only on networks you own or have authorization to monitor. Comply with local laws regarding network monitoring and data collection.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT — see [LICENSE](LICENSE).
