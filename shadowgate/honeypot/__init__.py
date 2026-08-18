"""ShadowGate Honeypot — Multi-protocol deception system."""

from shadowgate.honeypot.http_pot import HTTPHoneypot
from shadowgate.honeypot.ssh_pot import SSHHoneypot
from shadowgate.honeypot.ftp_pot import FTPHoneypot
from shadowgate.honeypot.smtp_pot import SMTPHoneypot

__all__ = ["HTTPHoneypot", "SSHHoneypot", "FTPHoneypot", "SMTPHoneypot"]
