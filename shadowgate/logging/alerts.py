"""Alert system for ShadowGate — Slack, Discord, Email notifications."""

import asyncio
import hashlib
import logging
import smtplib
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from string import Template
from typing import Any, Dict, Optional

import aiohttp

from shadowgate.config import Config

logger = logging.getLogger("shadowgate.alerts")

# Default webhook message templates
DEFAULT_SLACK_TEMPLATE = """{
    "attachments": [{
        "color": "$color",
        "title": "🛡️ ShadowGate Alert: $title",
        "text": "$message",
        "fields": [
            {"title": "Severity", "value": "$severity", "short": true},
            {"title": "Source", "value": "$source_ip", "short": true}
        ],
        "footer": "ShadowGate Security",
        "ts": $timestamp
    }]
}"""

DEFAULT_DISCORD_TEMPLATE = """{
    "embeds": [{
        "title": "🛡️ ShadowGate Alert: $title",
        "description": "$message",
        "color": $discord_color,
        "fields": [
            {"name": "Severity", "value": "$severity", "inline": true},
            {"name": "Source IP", "value": "$source_ip", "inline": true}
        ],
        "footer": {"text": "ShadowGate Security"}
    }]
}"""

SEVERITY_COLORS = {
    "low":      {"hex": "#36a64f", "slack": "good",    "discord": 3706415},
    "medium":   {"hex": "#f2c744", "slack": "warning", "discord": 15910724},
    "high":     {"hex": "#e74c3c", "slack": "danger",  "discord": 15158332},
    "critical": {"hex": "#8b0000", "slack": "danger",  "discord": 9109504},
}


class AlertManager:
    """Manages alert dispatching to Slack, Discord, and Email with cooldown."""

    def __init__(self, config: Config):
        self.config = config
        self.enabled = config.get("alerts", "enabled", default=False)
        self.cooldown = config.get("alerts", "cooldown", default=300)

        # Cooldown tracking: hash(title+severity) -> last_sent_timestamp
        self._cooldown_cache: Dict[str, float] = {}

        # Custom templates
        self._slack_template = config.get(
            "alerts", "slack", "message_template", default=None
        ) or DEFAULT_SLACK_TEMPLATE
        self._discord_template = config.get(
            "alerts", "discord", "message_template", default=None
        ) or DEFAULT_DISCORD_TEMPLATE

    def _is_on_cooldown(self, title: str, severity: str) -> bool:
        key = hashlib.md5(f"{title}:{severity}".encode()).hexdigest()
        now = time.time()
        if key in self._cooldown_cache:
            if now - self._cooldown_cache[key] < self.cooldown:
                return True
        self._cooldown_cache[key] = now
        return False

    async def send_alert(
        self,
        title: str,
        message: str,
        severity: str = "medium",
        data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Send an alert to all configured channels."""
        if not self.enabled:
            return

        if self._is_on_cooldown(title, severity):
            logger.debug(f"Alert on cooldown: {title}")
            return

        data = data or {}
        tasks = []

        # Slack
        slack_url = self.config.get("alerts", "slack", "webhook_url", default="")
        if slack_url:
            tasks.append(self._send_slack(slack_url, title, message, severity, data))

        # Discord
        discord_url = self.config.get("alerts", "discord", "webhook_url", default="")
        if discord_url:
            tasks.append(self._send_discord(discord_url, title, message, severity, data))

        # Email
        email_host = self.config.get("alerts", "email", "smtp_host", default="")
        if email_host:
            tasks.append(self._send_email(title, message, severity, data))

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    logger.error(f"Alert channel {i} failed: {result}")

    def _render_template(self, template_str: str, title: str, message: str,
                         severity: str, data: Dict[str, Any]) -> str:
        colors = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["medium"])
        template = Template(template_str)
        return template.safe_substitute(
            title=title,
            message=message,
            severity=severity.upper(),
            color=colors["slack"],
            discord_color=colors["discord"],
            source_ip=data.get("source_ip", "N/A"),
            protocol=data.get("protocol", "N/A"),
            timestamp=int(time.time()),
        )

    async def _send_slack(self, webhook_url: str, title: str, message: str,
                          severity: str, data: Dict[str, Any]) -> None:
        payload = self._render_template(self._slack_template, title, message, severity, data)
        async with aiohttp.ClientSession() as session:
            async with session.post(
                webhook_url,
                data=payload,
                headers={"Content-Type": "application/json"},
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status != 200:
                    logger.warning(f"Slack alert failed: HTTP {resp.status}")

    async def _send_discord(self, webhook_url: str, title: str, message: str,
                            severity: str, data: Dict[str, Any]) -> None:
        payload = self._render_template(self._discord_template, title, message, severity, data)
        async with aiohttp.ClientSession() as session:
            async with session.post(
                webhook_url,
                data=payload,
                headers={"Content-Type": "application/json"},
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status not in (200, 204):
                    logger.warning(f"Discord alert failed: HTTP {resp.status}")

    async def _send_email(self, title: str, message: str, severity: str,
                          data: Dict[str, Any]) -> None:
        smtp_host = self.config.get("alerts", "email", "smtp_host", default="")
        smtp_port = self.config.get("alerts", "email", "smtp_port", default=587)
        use_tls = self.config.get("alerts", "email", "use_tls", default=True)
        username = self.config.get("alerts", "email", "username", default="")
        password = self.config.get("alerts", "email", "password", default="")
        from_addr = self.config.get("alerts", "email", "from_address", default="")
        to_addrs = self.config.get("alerts", "email", "to_addresses", default=[])

        if not to_addrs:
            return

        colors = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["medium"])
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[🛡️ ShadowGate {severity.upper()}] {title}"
        msg["From"] = from_addr
        msg["To"] = ", ".join(to_addrs)

        html = f"""
        <html><body style="font-family: sans-serif; background: #f5f5f5; padding: 20px;">
        <div style="max-width: 600px; margin: 0 auto; background: #fff; border-radius: 8px;
            border-left: 4px solid {colors['hex']}; padding: 24px;">
            <h2 style="margin: 0 0 12px 0; color: #1a1a1a;">🛡️ {title}</h2>
            <p style="color: #555; line-height: 1.6;">{message}</p>
            <table style="margin-top: 16px; font-size: 14px;">
                <tr><td style="color: #888; padding: 4px 12px 4px 0;">Severity:</td>
                    <td><strong>{severity.upper()}</strong></td></tr>
                <tr><td style="color: #888; padding: 4px 12px 4px 0;">Source IP:</td>
                    <td>{data.get('source_ip', 'N/A')}</td></tr>
                <tr><td style="color: #888; padding: 4px 12px 4px 0;">Protocol:</td>
                    <td>{data.get('protocol', 'N/A')}</td></tr>
            </table>
            <hr style="margin: 20px 0; border: none; border-top: 1px solid #eee;">
            <p style="font-size: 12px; color: #999;">ShadowGate Security Alert System</p>
        </div></body></html>
        """
        msg.attach(MIMEText(message, "plain"))
        msg.attach(MIMEText(html, "html"))

        # Run SMTP in thread to avoid blocking
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, lambda: self._smtp_send(
            smtp_host, int(smtp_port), use_tls, username, password, from_addr, to_addrs, msg
        ))

    @staticmethod
    def _smtp_send(host, port, use_tls, username, password, from_addr, to_addrs, msg):
        try:
            if use_tls:
                server = smtplib.SMTP(host, port)
                server.starttls()
            else:
                server = smtplib.SMTP(host, port)
            if username and password:
                server.login(username, password)
            server.sendmail(from_addr, to_addrs, msg.as_string())
            server.quit()
        except Exception as e:
            logger.error(f"Email send failed: {e}")
