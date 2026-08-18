import asyncio
import time
from typing import Any, Dict, Optional
import aiohttp
import aiosmtplib
from email.message import EmailMessage

from shadowgate.logging.logger import get_logger

logger = get_logger(__name__)


class AlertManager:
    """Manages sending alerts via various channels with cooldown tracking to prevent spam."""

    def __init__(self, config: Any):
        self.config = config
        self.cooldowns: Dict[str, float] = {}
        # Default cooldown in seconds (e.g., 5 minutes)
        self.default_cooldown = self.config.get("alerting", "cooldown", default=300)

    async def send_alert(self, title: str, message: str, severity: str = "medium", data: Optional[Dict[str, Any]] = None) -> None:
        """Send an alert to all configured channels if not in cooldown."""
        alert_key = f"{title}:{severity}"
        current_time = time.time()
        
        # Check cooldown
        if alert_key in self.cooldowns:
            if current_time - self.cooldowns[alert_key] < self.default_cooldown:
                logger.debug("Alert suppressed due to cooldown", extra={"alert_key": alert_key})
                return
                
        self.cooldowns[alert_key] = current_time
        
        # Prepare data
        data = data or {}
        
        # Dispatch to configured channels
        tasks = []
        
        slack_webhook = self.config.get("alerting", "slack_webhook", default=None)
        if slack_webhook:
            tasks.append(self._send_slack(slack_webhook, title, message, severity, data))
            
        discord_webhook = self.config.get("alerting", "discord_webhook", default=None)
        if discord_webhook:
            tasks.append(self._send_discord(discord_webhook, title, message, severity, data))
            
        email_config = self.config.get("alerting", "email", default=None)
        if email_config and email_config.get("enabled"):
            tasks.append(self._send_email(email_config, title, message, severity, data))
            
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _send_slack(self, webhook_url: str, title: str, message: str, severity: str, data: Dict[str, Any]) -> None:
        """Send alert via Slack webhook."""
        colors = {
            "low": "#3498db",
            "medium": "#f1c40f",
            "high": "#e67e22",
            "critical": "#e74c3c"
        }
        color = colors.get(severity.lower(), "#95a5a6")
        
        payload = {
            "attachments": [
                {
                    "color": color,
                    "title": title,
                    "text": message,
                    "fields": [{"title": k, "value": str(v), "short": True} for k, v in data.items()],
                    "footer": "ShadowGate Alerting System"
                }
            ]
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=payload) as response:
                    if response.status >= 400:
                        logger.error(f"Failed to send Slack alert: {response.status}")
        except Exception as e:
            logger.error("Exception while sending Slack alert", extra={"error": str(e)})

    async def _send_discord(self, webhook_url: str, title: str, message: str, severity: str, data: Dict[str, Any]) -> None:
        """Send alert via Discord webhook."""
        colors = {
            "low": 3447003,      # Blue
            "medium": 15844367,  # Yellow
            "high": 15105570,    # Orange
            "critical": 15158332 # Red
        }
        color = colors.get(severity.lower(), 9807270) # Default grey
        
        embed = {
            "title": title,
            "description": message,
            "color": color,
            "fields": [{"name": k, "value": str(v), "inline": True} for k, v in data.items()],
            "footer": {"text": "ShadowGate Alerting System"}
        }
        
        payload = {"embeds": [embed]}
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=payload) as response:
                    if response.status >= 400:
                        logger.error(f"Failed to send Discord alert: {response.status}")
        except Exception as e:
            logger.error("Exception while sending Discord alert", extra={"error": str(e)})

    async def _send_email(self, email_config: Dict[str, Any], title: str, message: str, severity: str, data: Dict[str, Any]) -> None:
        """Send alert via email."""
        msg = EmailMessage()
        msg["Subject"] = f"[{severity.upper()}] ShadowGate Alert: {title}"
        msg["From"] = email_config.get("from_address")
        msg["To"] = email_config.get("to_address")
        
        body = f"Severity: {severity.upper()}\n\n{message}\n\n"
        if data:
            body += "Details:\n"
            for k, v in data.items():
                body += f"  {k}: {v}\n"
                
        msg.set_content(body)
        
        try:
            await aiosmtplib.send(
                msg,
                hostname=email_config.get("smtp_host"),
                port=email_config.get("smtp_port", 587),
                username=email_config.get("smtp_user"),
                password=email_config.get("smtp_password"),
                use_tls=email_config.get("use_tls", True)
            )
        except Exception as e:
            logger.error("Exception while sending Email alert", extra={"error": str(e)})
