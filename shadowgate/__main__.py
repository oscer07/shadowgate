"""ShadowGate CLI — Command-line interface for managing all services."""

import asyncio
import signal
import sys
from typing import Optional

import click

from shadowgate import __version__
from shadowgate.config import Config


def _get_config(config_path: Optional[str]) -> Config:
    """Load configuration with optional custom path."""
    try:
        return Config(config_path)
    except FileNotFoundError as e:
        click.secho(f"Error: {e}", fg="red", err=True)
        sys.exit(1)


def _setup_signal_handlers(loop: asyncio.AbstractEventLoop) -> None:
    """Register graceful shutdown handlers."""
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, lambda: asyncio.ensure_future(_shutdown(loop)))
        except NotImplementedError:
            # Windows doesn't support add_signal_handler
            pass


async def _shutdown(loop: asyncio.AbstractEventLoop) -> None:
    """Graceful shutdown of all async tasks."""
    click.echo("\n⏹  Shutting down ShadowGate...")
    tasks = [t for t in asyncio.all_tasks(loop) if t is not asyncio.current_task()]
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    loop.stop()


@click.group()
@click.version_option(__version__, prog_name="ShadowGate")
def cli():
    """🛡️ ShadowGate — Private Proxy Server & Honeypot Toolkit"""
    pass


@cli.command()
@click.option("--config", "-c", "config_path", default=None, help="Path to config file")
@click.option("--host", "-h", default=None, help="Proxy listen host")
@click.option("--port", "-p", default=None, type=int, help="Proxy listen port")
def proxy(config_path: Optional[str], host: Optional[str], port: Optional[int]):
    """Start the private proxy server."""
    config = _get_config(config_path)
    
    from shadowgate.proxy.server import ProxyServer
    from shadowgate.logging.logger import get_logger

    logger = get_logger("proxy", config)
    
    server = ProxyServer(
        config=config,
        host=host or config.get("proxy", "host", default="0.0.0.0"),
        port=port or config.get("proxy", "port", default=8080),
    )

    click.secho("🔒 Starting ShadowGate Proxy Server...", fg="green")
    click.echo(f"   Listening on {server.host}:{server.port}")
    
    asyncio.run(server.start())


@cli.command()
@click.option("--config", "-c", "config_path", default=None, help="Path to config file")
@click.option("--protocols", default="all", help="Comma-separated protocols: http,ssh,ftp,smtp,all")
def honeypot(config_path: Optional[str], protocols: str):
    """Start the honeypot system."""
    config = _get_config(config_path)
    
    from shadowgate.honeypot.http_pot import HTTPHoneypot
    from shadowgate.honeypot.ssh_pot import SSHHoneypot
    from shadowgate.honeypot.ftp_pot import FTPHoneypot
    from shadowgate.honeypot.smtp_pot import SMTPHoneypot
    from shadowgate.logging.logger import get_logger

    logger = get_logger("honeypot", config)
    proto_list = [p.strip().lower() for p in protocols.split(",")]
    run_all = "all" in proto_list
    
    pots = []
    hp_config = config.honeypot
    
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

    if not pots:
        click.secho("No honeypot protocols enabled.", fg="yellow")
        return

    click.secho(f"🍯 Starting ShadowGate Honeypot ({len(pots)} protocols)...", fg="green")

    async def run_all_pots():
        await asyncio.gather(*(pot.start() for pot in pots))

    asyncio.run(run_all_pots())


@cli.command()
@click.option("--config", "-c", "config_path", default=None, help="Path to config file")
@click.option("--host", default=None, help="Dashboard listen host")
@click.option("--port", default=None, type=int, help="Dashboard listen port")
def dashboard(config_path: Optional[str], host: Optional[str], port: Optional[int]):
    """Start the monitoring dashboard."""
    config = _get_config(config_path)
    
    from shadowgate.dashboard.app import create_app

    app = create_app(config)
    dash_host = host or config.get("dashboard", "host", default="127.0.0.1")
    dash_port = port or config.get("dashboard", "port", default=9090)

    click.secho("📊 Starting ShadowGate Dashboard...", fg="green")
    click.echo(f"   Dashboard at http://{dash_host}:{dash_port}")
    
    app.run(host=dash_host, port=dash_port, debug=False)


@cli.command(name="all")
@click.option("--config", "-c", "config_path", default=None, help="Path to config file")
def run_all(config_path: Optional[str]):
    """Start all services (proxy + honeypot + dashboard)."""
    config = _get_config(config_path)
    
    from shadowgate.proxy.server import ProxyServer
    from shadowgate.honeypot.http_pot import HTTPHoneypot
    from shadowgate.honeypot.ssh_pot import SSHHoneypot
    from shadowgate.honeypot.ftp_pot import FTPHoneypot
    from shadowgate.honeypot.smtp_pot import SMTPHoneypot
    from shadowgate.dashboard.app import create_app
    from shadowgate.logging.logger import get_logger

    logger = get_logger("shadowgate", config)

    click.secho("\n🛡️  ShadowGate — Starting All Services", fg="green", bold=True)
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
    click.echo(f"   🍯 Honeypots → {len(pots)} protocols")

    dash_host = config.get("dashboard", "host", default="127.0.0.1")
    dash_port = config.get("dashboard", "port", default=9090)
    click.echo(f"   📊 Dashboard → http://{dash_host}:{dash_port}")
    click.echo("=" * 45)

    async def run_all_services():
        tasks = [proxy_server.start()]
        tasks.extend(pot.start() for pot in pots)
        await asyncio.gather(*tasks)

    import threading
    # Run dashboard in a thread (Flask is sync)
    app = create_app(config)
    dash_thread = threading.Thread(
        target=app.run,
        kwargs={"host": dash_host, "port": dash_port, "debug": False},
        daemon=True,
    )
    dash_thread.start()

    asyncio.run(run_all_services())


if __name__ == "__main__":
    cli()
