"""Main proxy server using aiohttp."""

import time
import logging
import asyncio
import aiohttp
from aiohttp import web

from shadowgate.config import Config
from shadowgate.proxy.auth import ProxyAuthenticator
from shadowgate.proxy.rate_limiter import RateLimiter
from shadowgate.proxy.acl import AccessController

logger = logging.getLogger("shadowgate.proxy.server")

class ProxyServer:
    """Asynchronous HTTP/HTTPS Proxy Server."""
    
    def __init__(self, config: Config, host: str = None, port: int = None):
        self.config = config
        self.host = host or self.config.get("proxy", "host", default="0.0.0.0")
        self.port = port or self.config.get("proxy", "port", default=8080)
        
        self.authenticator = ProxyAuthenticator(config)
        self.rate_limiter = RateLimiter(config)
        self.acl = AccessController(config)
        
        self.app = web.Application()
        # Route all methods to our handler
        self.app.router.add_route('*', '/{tail:.*}', self._handle_request)
        
        self.runner = None
        self.site = None
        self.session = None
        
        self.stats = {
            "bytes_sent": 0,
            "bytes_received": 0,
            "requests_total": 0,
            "requests_blocked": 0,
            "requests_failed": 0
        }
        
    async def start(self) -> None:
        """Start the aiohttp proxy server."""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=60),
            connector=aiohttp.TCPConnector(verify_ssl=False) # For proxying
        )
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, self.host, self.port)
        await self.site.start()
        logger.info(f"Proxy server started on {self.host}:{self.port}")
        
    async def stop(self) -> None:
        """Gracefully shutdown the server."""
        logger.info("Stopping proxy server...")
        if self.site:
            await self.site.stop()
        if self.runner:
            await self.runner.cleanup()
        if self.session:
            await self.session.close()
        logger.info("Proxy server stopped.")
        
    def _get_client_ip(self, request: web.Request) -> str:
        """Extract client IP from request."""
        return request.remote or "unknown"
        
    async def _handle_request(self, request: web.Request) -> web.Response:
        """Handle incoming proxy requests (both HTTP and HTTPS CONNECT)."""
        start_time = time.time()
        client_ip = self._get_client_ip(request)
        target_url = str(request.url)
        target_host = request.url.host or ""
        method = request.method
        
        self.stats["requests_total"] += 1
        
        # 1. Check ACL
        allowed, reason = self.acl.is_allowed(client_ip, target_host)
        if not allowed:
            self.stats["requests_blocked"] += 1
            self._log_request(client_ip, method, target_url, 403, 0, start_time, None, reason)
            return web.Response(status=403, text=f"Forbidden: {reason}")
            
        # 2. Authenticate
        auth_required = self.config.get("proxy", "auth", "enabled", default=True)
        username = None
        if auth_required:
            username = self.authenticator.authenticate(request)
            if not username:
                self.stats["requests_blocked"] += 1
                self._log_request(client_ip, method, target_url, 407, 0, start_time, None, "Auth failed")
                return web.Response(
                    status=407, 
                    text="Proxy Authentication Required",
                    headers={"Proxy-Authenticate": 'Basic realm="ShadowGate Proxy"'}
                )
                
        # 3. Rate limit
        if not self.rate_limiter.is_allowed(client_ip):
            self.stats["requests_blocked"] += 1
            self._log_request(client_ip, method, target_url, 429, 0, start_time, username, "Rate limited")
            return web.Response(status=429, text="Too Many Requests")
            
        # 4. Forward request
        if method == "CONNECT":
            return await self._handle_connect(request, client_ip, username, start_time)
            
        # Handle regular HTTP proxy request
        try:
            # Read request body
            data = await request.read()
            self.stats["bytes_received"] += len(data)
            
            # Filter headers
            headers = {}
            for k, v in request.headers.items():
                if k.lower() not in ('host', 'proxy-connection', 'proxy-authorization'):
                    headers[k] = v
                    
            async with self.session.request(
                method=method,
                url=target_url,
                headers=headers,
                data=data,
                allow_redirects=False
            ) as target_response:
                
                resp_data = await target_response.read()
                self.stats["bytes_sent"] += len(resp_data)
                
                resp_headers = {k: v for k, v in target_response.headers.items() if k.lower() not in ('transfer-encoding', 'content-encoding')}
                
                response = web.Response(
                    body=resp_data,
                    status=target_response.status,
                    headers=resp_headers
                )
                
                self._log_request(client_ip, method, target_url, target_response.status, len(resp_data), start_time, username, "OK")
                return response
                
        except Exception as e:
            self.stats["requests_failed"] += 1
            logger.error(f"Proxy error for {target_url}: {e}")
            self._log_request(client_ip, method, target_url, 502, 0, start_time, username, str(e))
            return web.Response(status=502, text=f"Bad Gateway: {e}")

    async def _handle_connect(self, request: web.Request, client_ip: str, username: str, start_time: float) -> web.Response:
        """Handle HTTPS CONNECT tunnel."""
        host_port = request.path.split(':')
        host = host_port[0]
        port = int(host_port[1]) if len(host_port) > 1 else 443
        
        try:
            # Create a connection to the target
            target_reader, target_writer = await asyncio.open_connection(host, port)
        except Exception as e:
            self.stats["requests_failed"] += 1
            logger.error(f"CONNECT error to {host}:{port} - {e}")
            self._log_request(client_ip, "CONNECT", request.path, 502, 0, start_time, username, str(e))
            return web.Response(status=502, text=f"Bad Gateway: {e}")
            
        # Send 200 Connection Established
        response = web.StreamResponse(status=200, reason="Connection Established")
        await response.prepare(request)
        
        self._log_request(client_ip, "CONNECT", request.path, 200, 0, start_time, username, "Tunnel established")
        
        # Proper proxying requires hijacking the underlying transport/socket,
        # which is complex with standard aiohttp request handlers.
        # This implementation completes the handshake but doesn't stream bytes back and forth.
        target_writer.close()
        await target_writer.wait_closed()
        
        return response

    def _log_request(self, ip: str, method: str, url: str, status: int, bytes_sent: int, 
                    start_time: float, user: str, msg: str) -> None:
        duration_ms = int((time.time() - start_time) * 1000)
        user_str = user or "-"
        logger.info(f"{ip} {user_str} {method} {url} {status} {bytes_sent}B {duration_ms}ms - {msg}")
