# Changelog

All notable changes to ShadowGate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [1.1.0] - 2024-03-15

### Added
- Telnet honeypot emulating BusyBox/IoT devices
- Joomla and Drupal fake login pages in HTTP honeypot
- SSH honeypot expanded with 20+ realistic commands (wget, curl, netstat, ps, df, free, ping, etc.)
- Session recording for SSH and Telnet honeypots
- Proxy chain support (upstream SOCKS5/HTTP proxy)
- Dashboard login authentication (optional)
- CSV and JSON event export from dashboard
- Credentials capture viewer in dashboard
- Custom webhook message templates for Slack and Discord alerts
- Connection status indicator in dashboard

### Changed
- Rate limiter upgraded to async-safe with `time.monotonic()` (fixes Windows clock drift)
- EventStore uses running counters for O(1) stats (fixes memory leak on long runs)
- Dashboard JavaScript rewritten with better animations and error handling
- HTTP honeypot serves realistic HTML with proper CSS styling
- Fake `.env` file now contains realistic AWS, Stripe, and database credentials
- Alerts system supports customizable message templates
- Logger creates log directory automatically

### Fixed
- Proxy CONNECT tunnel now supports bidirectional byte streaming
- Rate limiter no longer fails on Windows due to clock drift
- SMTP honeypot correctly handles multi-line DATA termination
- EventStore no longer grows unbounded (uses bounded deque + running counters)
- Dashboard gracefully handles fetch errors with "Reconnecting" state

### Security
- Dashboard login support with session-based auth
- CSRF protection via Flask session
- Proxy strips X-API-Key header before forwarding

## [1.0.0] - 2024-01-15

### Added
- Private HTTP/HTTPS proxy server with authentication
- Multi-protocol honeypot (HTTP, SSH, FTP, SMTP)
- Real-time monitoring dashboard
- Structured JSON logging with rotation
- Alert system (Slack, Discord, Email webhooks)
- Docker and Docker Compose support
- CLI interface with subcommands
- IP whitelist/blacklist access control
- Token-bucket rate limiting
- Attacker fingerprinting with GeoIP
- Comprehensive test suite
