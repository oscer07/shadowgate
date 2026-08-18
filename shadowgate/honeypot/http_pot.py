import asyncio
from aiohttp import web
from shadowgate.honeypot.base import BaseHoneypot
from shadowgate.honeypot.fingerprint import Fingerprinter

class HTTPHoneypot(BaseHoneypot):
    PROTOCOL = "http"
    
    def __init__(self, config):
        super().__init__(config)
        self.fingerprinter = Fingerprinter()
        self.app = web.Application(middlewares=[self._middleware])
        self.runner = None
        self.site = None
        self._setup_routes()
        
    def _setup_routes(self):
        self.app.router.add_get('/wp-login.php', self._handle_wp_login)
        self.app.router.add_post('/wp-login.php', self._handle_wp_login_post)
        self.app.router.add_get('/admin', self._handle_admin)
        self.app.router.add_get('/phpmyadmin', self._handle_pma)
        self.app.router.add_get('/.env', self._handle_env)
        self.app.router.add_get('/api/v1/users', self._handle_api)
        self.app.router.add_get('/robots.txt', self._handle_robots)
        self.app.router.add_route('*', '/{tail:.*}', self._handle_default)

    @web.middleware
    async def _middleware(self, request, handler):
        ip = request.remote
        ua = request.headers.get('User-Agent', '')
        fingerprint = self.fingerprinter.get_fingerprint(ip, dict(request.headers), ua)
        
        self._record_event(
            event_type="http_request",
            source_ip=ip,
            method=request.method,
            path=request.path,
            headers=dict(request.headers),
            query=dict(request.query),
            body=await request.text(),
            fingerprint=fingerprint
        )
        
        response = await handler(request)
        response.headers['Server'] = 'Apache/2.4.41 (Ubuntu)'
        response.headers['X-Powered-By'] = 'PHP/7.4.3'
        return response

    async def start(self):
        port = self.config.get("http_port", 8080)
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, '0.0.0.0', port)
        await self.site.start()
        self._running = True

    async def stop(self):
        if self.runner:
            await self.runner.cleanup()
        self._running = False

    async def _handle_wp_login(self, request):
        return web.Response(text='<html><body><form method="post"><input name="log"><input name="pwd" type="password"></form></body></html>', content_type='text/html')

    async def _handle_wp_login_post(self, request):
        data = await request.post()
        self._record_event("http_login_attempt", request.remote, target="wordpress", username=data.get('log'), password=data.get('pwd'))
        return web.Response(text='Error: incorrect password', content_type='text/html')

    async def _handle_admin(self, request):
        return web.Response(text='<html><body>Admin Panel</body></html>', content_type='text/html')

    async def _handle_pma(self, request):
        return web.Response(text='<html><body>phpMyAdmin Login</body></html>', content_type='text/html')

    async def _handle_env(self, request):
        self._record_event("http_sensitive_file", request.remote, file=".env")
        return web.Response(text='DB_PASSWORD=secret', content_type='text/plain')

    async def _handle_api(self, request):
        return web.json_response({"users": [{"id": 1, "username": "admin"}]})

    async def _handle_robots(self, request):
        return web.Response(text='User-agent: *\nDisallow: /admin/', content_type='text/plain')

    async def _handle_default(self, request):
        return web.Response(text='<html><body>404 Not Found</body></html>', content_type='text/html', status=404)
