"""Tests for ShadowGate honeypot components."""

import pytest
from shadowgate.config import Config
from shadowgate.honeypot.http_pot import HTTPHoneypot
from shadowgate.honeypot.ssh_pot import SSHHoneypot
from shadowgate.honeypot.ftp_pot import FTPHoneypot
from shadowgate.honeypot.smtp_pot import SMTPHoneypot
from shadowgate.honeypot.fingerprint import Fingerprinter


class TestHTTPHoneypot:
    def test_init(self):
        config = Config()
        pot = HTTPHoneypot(config)
        assert pot.PROTOCOL == "http"


class TestSSHHoneypot:
    def test_init(self):
        config = Config()
        pot = SSHHoneypot(config)
        assert pot.PROTOCOL == "ssh"


class TestFTPHoneypot:
    def test_init(self):
        config = Config()
        pot = FTPHoneypot(config)
        assert pot.PROTOCOL == "ftp"


class TestSMTPHoneypot:
    def test_init(self):
        config = Config()
        pot = SMTPHoneypot(config)
        assert pot.PROTOCOL == "smtp"


class TestFingerprinter:
    def test_init(self):
        fp = Fingerprinter()
        assert fp is not None

    def test_known_scanner_detection(self):
        fp = Fingerprinter()
        result = fp._check_known_scanner(
            {"User-Agent": "Nmap Scripting Engine"},
            "Nmap Scripting Engine"
        )
        assert result is not None

    def test_user_agent_parsing(self):
        fp = Fingerprinter()
        result = fp._parse_user_agent(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        )
        assert "raw" in result
