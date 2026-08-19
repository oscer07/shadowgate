"""ShadowGate CLI — Command-line interface for managing all services."""

import asyncio
import signal
import sys
from typing import Optional

import click

from shadowgate import __version__
from shadowgate.config import Config


def _get_config(config_path: Optional[str]) -> Config:
    try:
        return Config(config_path)
    except FileNotFoundError as e:
        click.secho(f"Error: {e}", fg="red", err=True)
        sys.exit(1)


@click.group()
@click.version_option(__version__, prog_name="ShadowGate")
def cli():
    """🛡️ ShadowGate — Private Proxy Server & Honeypot Toolkit"""
    pass


@cli.command()
@click.option("--config", "-c", "config_path", default=None, help="Path to config file")
@click.option("--host", "-h", default=None, help="Proxy listen host")
@click.option("--port", "-p", default=None, type=int, help="Proxy listen port")
def proxy(config_path, host, port):
    """Start the private proxy server."""
    config = _get_config(config_path)
    from shadowgate.proxy.server import ProxyServer
    from shadowgate.logging.logger import get_logger

    get_logger("proxy", config)
    server = ProxyServer(
        config=config,
        host=host or config.get("proxy", "host", default="0.0.0.0"),
        port=port or config.get("proxy", "port", default=8080),
    )
    click.secho("\n🔒 ShadowGate Proxy Server", fg="green", bold=True)
    click.echo(f"   Listening on {server.host}:{server.port}")
    click.echo()
    asyncio.run(server.start())


@cli.command()
@click.option("--config", "-c", "config_path", default=None, help="Path to config file")
@click.option("--protocols", default="all", help="Comma-separated: http,ssh,ftp,smtp,telnet,all")
def honeypot(config_path, protocols):
    """Start the honeypot system."""
    config = _get_config(config_path)
    from shadowgate.honeypot.http_pot import HTTPHoneypot
    from shadowgate.honeypot.ssh_pot import SSHHoneypot
    from shadowgate.honeypot.ftp_pot import FTPHoneypot
    from shadowgate.honeypot.smtp_pot import SMTPHoneypot
    from shadowgate.honeypot.telnet_pot import TelnetHoneypot
    from shadowgate.logging.logger import get_logger

    get_logger("honeypot", config)
    proto_list = [p.strip().lower() for p in protocols.split(",")]
    run_all = "all" in proto_list
    hp_config = config.honeypot
    pots = []

    if run_all or "http" in proto_list:
        if hp_config.get("http", {}).get("enabled", True):
            pots.append(HTTPHoneypot(config))
            click.echo("   🌐 HTTP honeypot enabled")
    if run_all or "ssh" in proto_list:
        if hp_config.get("ssh", {}).get("enabled", True):
            pots.append(SSHHoneypot(config))
            click.echo("   🔑 SSH honeypot enabled")
    if run_all or "ftp" in proto_list:
        if hp_config.get("ftp", {}).get("enabled", True):
            pots.append(FTPHoneypot(config))
            click.echo("   📁 FTP honeypot enabled")
    if run_all or "smtp" in proto_list:
        if hp_config.get("smtp", {}).get("enabled", True):
            pots.append(SMTPHoneypot(config))
            click.echo("   ✉️  SMTP honeypot enabled")
    if run_all or "telnet" in proto_list:
        if hp_config.get("telnet", {}).get("enabled", True):
            pots.append(TelnetHoneypot(config))
            click.echo("   📟 Telnet honeypot enabled")

    if not pots:
        click.secho("No honeypot protocols enabled.", fg="yellow")
        return

    click.secho(f"\n🍯 ShadowGate Honeypot — {len(pots)} protocols", fg="green", bold=True)
    click.echo()

    async def run_pots():
        await asyncio.gather(*(pot.start() for pot in pots))
        # Keep running
        try:
            while True:
                await asyncio.sleep(3600)
        except asyncio.CancelledError:
            for pot in pots:
                await pot.stop()

    asyncio.run(run_pots())


@cli.command()
@click.option("--config", "-c", "config_path", default=None, help="Path to config file")
@click.option("--host", default=None, help="Dashboard listen host")
@click.option("--port", default=None, type=int, help="Dashboard listen port")
def dashboard(config_path, host, port):
    """Start the monitoring dashboard."""
    config = _get_config(config_path)
    from shadowgate.dashboard.app import create_app

    app = create_app(config)
    dash_host = host or config.get("dashboard", "host", default="127.0.0.1")
    dash_port = port or config.get("dashboard", "port", default=9090)
    click.secho("\n📊 ShadowGate Dashboard", fg="green", bold=True)
    click.echo(f"   http://{dash_host}:{dash_port}")
    click.echo()
    app.run(host=dash_host, port=dash_port, debug=False)


@cli.command(name="all")
@click.option("--config", "-c", "config_path", default=None, help="Path to config file")
def run_all(config_path):
    """Start all services (proxy + honeypot + dashboard)."""
    config = _get_config(config_path)
    from shadowgate.proxy.server import ProxyServer
    from shadowgate.honeypot.http_pot import HTTPHoneypot
    from shadowgate.honeypot.ssh_pot import SSHHoneypot
    from shadowgate.honeypot.ftp_pot import FTPHoneypot
    from shadowgate.honeypot.smtp_pot import SMTPHoneypot
    from shadowgate.honeypot.telnet_pot import TelnetHoneypot
    from shadowgate.dashboard.app import create_app
    from shadowgate.logging.logger import get_logger

    get_logger("shadowgate", config)

    click.secho("\n🛡️  ShadowGate v" + __version__, fg="green", bold=True)
    click.echo("=" * 45)

    proxy_server = ProxyServer(config=config)
    click.echo(f"   🔒 Proxy     → {proxy_server.host}:{proxy_server.port}")

    pots = []
    hp_config = config.honeypot
    if hp_config.get("http", {}).get("enabled"):
        pots.append(HTTPHoneypot(config))
    if hp_config.get("ssh", {}).get("enabled"):
        pots.append(SSHHoneypot(config))
    if hp_config.get("ftp", {}).get("enabled"):
        pots.append(FTPHoneypot(config))
    if hp_config.get("smtp", {}).get("enabled"):
        pots.append(SMTPHoneypot(config))
    if hp_config.get("telnet", {}).get("enabled", True):
        pots.append(TelnetHoneypot(config))
    click.echo(f"   🍯 Honeypots → {len(pots)} protocols")

    dash_host = config.get("dashboard", "host", default="127.0.0.1")
    dash_port = config.get("dashboard", "port", default=9090)
    click.echo(f"   📊 Dashboard → http://{dash_host}:{dash_port}")
    click.echo("=" * 45 + "\n")

    import threading
    app = create_app(config)
    dash_thread = threading.Thread(
        target=app.run,
        kwargs={"host": dash_host, "port": dash_port, "debug": False},
        daemon=True,
    )
    dash_thread.start()

    async def run_services():
        tasks = [proxy_server.start()]
        tasks.extend(pot.start() for pot in pots)
        await asyncio.gather(*tasks)

    asyncio.run(run_services())


if __name__ == "__main__":
    cli()
