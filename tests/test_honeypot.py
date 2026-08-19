"""Tests for ShadowGate honeypot components."""

import pytest
from shadowgate.config import Config
from shadowgate.honeypot.http_pot import HTTPHoneypot
from shadowgate.honeypot.ssh_pot import SSHHoneypot
from shadowgate.honeypot.ftp_pot import FTPHoneypot
from shadowgate.honeypot.smtp_pot import SMTPHoneypot
from shadowgate.honeypot.telnet_pot import TelnetHoneypot
from shadowgate.honeypot.fingerprint import Fingerprinter


class TestHTTPHoneypot:
    def test_init(self):
        config = Config()
        pot = HTTPHoneypot(config)
        assert pot.PROTOCOL == "http"

    def test_has_realistic_pages(self):
        config = Config()
        pot = HTTPHoneypot(config)
        assert "WordPress" in pot.WP_LOGIN_HTML
        assert "phpMyAdmin" in pot.PMA_LOGIN_HTML
        assert "Joomla" in pot.JOOMLA_LOGIN_HTML
        assert "Drupal" in pot.DRUPAL_LOGIN_HTML


class TestSSHHoneypot:
    def test_init(self):
        config = Config()
        pot = SSHHoneypot(config)
        assert pot.PROTOCOL == "ssh"

    def test_command_execution(self):
        config = Config()
        pot = SSHHoneypot(config)
        env = {"HOME": "/home/admin", "USER": "admin", "HOSTNAME": "test"}
        assert "admin" in pot._execute_command("whoami", "/home/admin", "admin", env)
        assert "/home/admin" in pot._execute_command("pwd", "/home/admin", "admin", env)
        assert pot._execute_command("exit", "/home/admin", "admin", env) is None
        assert "command not found" in pot._execute_command("nonexistent", "/home/admin", "admin", env)

    def test_ls_command(self):
        config = Config()
        pot = SSHHoneypot(config)
        env = {"USER": "admin"}
        output = pot._execute_command("ls", "/home/admin", "admin", env)
        assert "Desktop" in output


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


class TestTelnetHoneypot:
    def test_init(self):
        config = Config()
        pot = TelnetHoneypot(config)
        assert pot.PROTOCOL == "telnet"

    def test_command_execution(self):
        config = Config()
        pot = TelnetHoneypot(config)
        assert "admin" in pot._run_command("whoami", "admin")
        assert pot._run_command("exit", "admin") is None
        assert "not found" in pot._run_command("nonexistent", "admin")


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
