"""ShadowGate Proxy Server — Async HTTP/HTTPS forward proxy with tunneling."""

import time
import logging
import asyncio

import aiohttp
from aiohttp import web

from shadowgate.config import Config
from shadowgate.proxy.auth import ProxyAuthenticator
from shadowgate.proxy.rate_limiter import RateLimiter
from shadowgate.proxy.acl import AccessController
from shadowgate.logging.logger import event_store

logger = logging.getLogger("shadowgate.proxy.server")


class ProxyServer:
    """Asynchronous HTTP/HTTPS Proxy Server with CONNECT tunneling."""

    def __init__(self, config: Config, host: str = None, port: int = None):
        self.config = config
        self.host = host or self.config.get("proxy", "host", default="0.0.0.0")
        self.port = port or self.config.get("proxy", "port", default=8080)

        self.authenticator = ProxyAuthenticator(config)
        self.rate_limiter = RateLimiter(config)
        self.acl = AccessController(config)

        # Proxy chaining (upstream proxy)
        self.upstream_proxy = self.config.get("proxy", "upstream_proxy", default=None)

        self.app = web.Application()
        self.app.router.add_route('CONNECT', '/{tail:.*}', self._handle_connect)
        self.app.router.add_route('*', '/{tail:.*}', self._handle_request)

        self.runner = None
        self.site = None
        self.session = None

        self.stats = {
            "bytes_sent": 0,
            "bytes_received": 0,
            "requests_total": 0,
            "requests_blocked": 0,
            "requests_failed": 0,
            "active_tunnels": 0,
        }

    async def start(self) -> None:
        """Start the proxy server."""
        connector = aiohttp.TCPConnector(ssl=False, limit=self.config.get("proxy", "max_connections", default=100))
        timeout = aiohttp.ClientTimeout(total=self.config.get("proxy", "timeout", default=30))
        self.session = aiohttp.ClientSession(connector=connector, timeout=timeout)
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, self.host, self.port)
        await self.site.start()
        logger.info(f"Proxy server started on {self.host}:{self.port}")
        # Keep running
        try:
            while True:
                await asyncio.sleep(3600)
        except asyncio.CancelledError:
            await self.stop()

    async def stop(self) -> None:
        """Gracefully shutdown."""
        logger.info("Stopping proxy server...")
        if self.site:
            await self.site.stop()
        if self.runner:
            await self.runner.cleanup()
        if self.session:
            await self.session.close()
        logger.info("Proxy server stopped.")

    def _get_client_ip(self, request: web.Request) -> str:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.remote or "unknown"

    def _check_access(self, request: web.Request, client_ip: str, target_host: str, method: str, target_url: str, start_time: float):
        """Run ACL, auth, rate limit checks. Returns web.Response on failure, None on success + username."""
        # ACL
        allowed, reason = self.acl.is_allowed(client_ip, target_host)
        if not allowed:
            self.stats["requests_blocked"] += 1
            self._log_request(client_ip, method, target_url, 403, 0, start_time, None, reason)
            return web.Response(status=403, text=f"Forbidden: {reason}"), None

        # Auth
        auth_required = self.config.get("proxy", "auth", "enabled", default=True)
        username = None
        if auth_required:
            username = self.authenticator.authenticate(request)
            if not username:
                self.stats["requests_blocked"] += 1
                self._log_request(client_ip, method, target_url, 407, 0, start_time, None, "Auth failed")
                return web.Response(
                    status=407, text="Proxy Authentication Required",
                    headers={"Proxy-Authenticate": 'Basic realm="ShadowGate Proxy"'},
                ), None

        # Rate limit
        if not self.rate_limiter.is_allowed(client_ip):
            self.stats["requests_blocked"] += 1
            self._log_request(client_ip, method, target_url, 429, 0, start_time, username, "Rate limited")
            return web.Response(status=429, text="Too Many Requests"), None

        return None, username

    async def _handle_request(self, request: web.Request) -> web.Response:
        """Handle HTTP proxy requests."""
        start_time = time.time()
        client_ip = self._get_client_ip(request)
        target_url = str(request.url)
        target_host = request.url.host or ""
        method = request.method
        self.stats["requests_total"] += 1

        # Record in event store for dashboard
        event_store.add_event({
            "protocol": "proxy",
            "event_type": "proxy_request",
            "source_ip": client_ip,
            "method": method,
            "url": target_url,
        })

        # Access checks
        error_response, username = self._check_access(
            request, client_ip, target_host, method, target_url, start_time
        )
        if error_response:
            return error_response

        # Forward request
        try:
            data = await request.read()
            self.stats["bytes_received"] += len(data)

            headers = {}
            for k, v in request.headers.items():
                if k.lower() not in ('host', 'proxy-connection', 'proxy-authorization', 'x-api-key'):
                    headers[k] = v

            # Proxy chaining support
            proxy_url = self.upstream_proxy if self.upstream_proxy else None

            async with self.session.request(
                method=method, url=target_url, headers=headers,
                data=data, allow_redirects=False, proxy=proxy_url,
            ) as resp:
                resp_data = await resp.read()
                self.stats["bytes_sent"] += len(resp_data)

                resp_headers = {
                    k: v for k, v in resp.headers.items()
                    if k.lower() not in ('transfer-encoding', 'content-encoding', 'content-length')
                }

                self._log_request(
                    client_ip, method, target_url, resp.status,
                    len(resp_data), start_time, username, "OK",
                )
                return web.Response(body=resp_data, status=resp.status, headers=resp_headers)

        except asyncio.TimeoutError:
            self.stats["requests_failed"] += 1
            self._log_request(client_ip, method, target_url, 504, 0, start_time, username, "Timeout")
            return web.Response(status=504, text="Gateway Timeout")
        except Exception as e:
            self.stats["requests_failed"] += 1
            logger.error(f"Proxy error: {e}")
            self._log_request(client_ip, method, target_url, 502, 0, start_time, username, str(e))
            return web.Response(status=502, text=f"Bad Gateway: {e}")

    async def _handle_connect(self, request: web.Request) -> web.StreamResponse:
        """Handle HTTPS CONNECT with full bidirectional byte streaming."""
        start_time = time.time()
        client_ip = self._get_client_ip(request)
        connect_target = request.path_qs
        self.stats["requests_total"] += 1

        # Parse host:port
        if ":" in connect_target:
            host, port_str = connect_target.rsplit(":", 1)
            port = int(port_str)
        else:
            host = connect_target
            port = 443

        event_store.add_event({
            "protocol": "proxy",
            "event_type": "proxy_connect",
            "source_ip": client_ip,
            "target": f"{host}:{port}",
        })

        # Access checks
        error_response, username = self._check_access(
            request, client_ip, host, "CONNECT", connect_target, start_time
        )
        if error_response:
            return error_response

        # Connect to target
        try:
            target_reader, target_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=10
            )
        except Exception as e:
            self.stats["requests_failed"] += 1
            self._log_request(client_ip, "CONNECT", connect_target, 502, 0, start_time, username, str(e))
            return web.Response(status=502, text=f"Bad Gateway: {e}")

        # Send 200 OK
        response = web.StreamResponse(status=200, reason="Connection Established")
        response.force_close()
        await response.prepare(request)

        self.stats["active_tunnels"] += 1
        self._log_request(client_ip, "CONNECT", connect_target, 200, 0, start_time, username, "Tunnel open")

        # Bidirectional pipe
        transport = request.transport
        if transport is None:
            target_writer.close()
            return response

        async def _pipe(reader, writer, label):
            """Pipe data from reader to writer."""
            try:
                while True:
                    data = await reader.read(65536)
                    if not data:
                        break
                    writer.write(data)
                    await writer.drain()
                    if label == "upstream":
                        self.stats["bytes_sent"] += len(data)
                    else:
                        self.stats["bytes_received"] += len(data)
            except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
                pass
            finally:
                try:
                    writer.close()
                except Exception:
                    pass

        # Get the client reader/writer from the transport
        client_reader = request.content
        
        try:
            # Run both directions concurrently
            await asyncio.gather(
                _pipe(client_reader, target_writer, "upstream"),
                _pipe(target_reader, response, "downstream"),
                return_exceptions=True,
            )
        finally:
            self.stats["active_tunnels"] -= 1
            try:
                target_writer.close()
            except Exception:
                pass

        return response

    def _log_request(self, ip: str, method: str, url: str, status: int,
                     bytes_sent: int, start_time: float, user: str, msg: str) -> None:
        duration_ms = int((time.time() - start_time) * 1000)
        user_str = user or "-"
        logger.info(
            f"{ip} {user_str} {method} {url} {status} {bytes_sent}B {duration_ms}ms - {msg}"
        )
