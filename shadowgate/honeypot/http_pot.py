"""HTTP Honeypot — Fake web applications with realistic login pages."""

import json
from aiohttp import web
from shadowgate.honeypot.base import BaseHoneypot
from shadowgate.honeypot.fingerprint import Fingerprinter


class HTTPHoneypot(BaseHoneypot):
    """HTTP honeypot serving fake vulnerable web applications."""
    
    PROTOCOL = "http"
    
    # --- Realistic HTML Templates ---
    
    WP_LOGIN_HTML = '''<!DOCTYPE html>
<html lang="en-US">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Log In &lsaquo; Company Blog &#8212; WordPress</title>
    <style>
        body { background: #f1f1f1; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        #login { width: 320px; margin: 100px auto; padding: 0; }
        #login h1 a { background-image: url(data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA0MDAgNDAwIj48cGF0aCBmaWxsPSIjMDA3MzlkIiBkPSJNMjAwIDEwYy0xMDQuOSAwLTE5MCA4NS4xLTE5MCAxOTBzODUuMSAxOTAgMTkwIDE5MCAxOTAtODUuMSAxOTAtMTkwUzMwNC45IDEwIDIwMCAxMHoiLz48L3N2Zz4=);
            background-size: 84px; background-position: center; background-repeat: no-repeat;
            width: 84px; height: 84px; display: block; margin: 0 auto 25px; text-indent: -9999px; }
        .login form { margin-top: 20px; background: #fff; border: 1px solid #c3c4c7; border-radius: 4px;
            box-shadow: 0 1px 3px rgba(0,0,0,.04); padding: 26px 24px; }
        .login label { font-size: 14px; color: #1e1e1e; }
        .login input[type=text], .login input[type=password] { width: 100%; padding: 5px 10px;
            font-size: 24px; margin: 2px 0 16px; border: 1px solid #8c8f94; border-radius: 4px;
            box-sizing: border-box; }
        .login .button-primary { width: 100%; padding: 8px; background: #2271b1; border: 1px solid #2271b1;
            border-radius: 4px; color: #fff; font-size: 14px; cursor: pointer; margin-top: 10px; }
        .login .button-primary:hover { background: #135e96; }
        .login #nav, .login #backtoblog { padding: 0 24px; text-align: center; }
        .login #nav a, .login #backtoblog a { color: #50575e; text-decoration: none; font-size: 13px; }
        p.forgetmenot { display: flex; align-items: center; gap: 6px; }
    </style>
</head>
<body class="login">
    <div id="login">
        <h1><a href="#" title="Company Blog">Company Blog</a></h1>
        <form method="post" action="/wp-login.php">
            <p><label for="user_login">Username or Email Address</label>
            <input type="text" name="log" id="user_login" autocomplete="username" required></p>
            <p><label for="user_pass">Password</label>
            <input type="password" name="pwd" id="user_pass" autocomplete="current-password" required></p>
            <p class="forgetmenot"><input name="rememberme" type="checkbox" id="rememberme" value="forever">
            <label for="rememberme">Remember Me</label></p>
            <p class="submit"><input type="submit" name="wp-submit" class="button button-primary" value="Log In"></p>
            <input type="hidden" name="redirect_to" value="/wp-admin/">
        </form>
        <p id="nav"><a href="/wp-login.php?action=lostpassword">Lost your password?</a></p>
        <p id="backtoblog"><a href="/">&larr; Go to Company Blog</a></p>
    </div>
</body>
</html>'''

    WP_LOGIN_ERROR_HTML = '''<!DOCTYPE html>
<html lang="en-US">
<head><title>Log In &lsaquo; Company Blog &#8212; WordPress</title>
<style>
    body { background: #f1f1f1; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    #login { width: 320px; margin: 60px auto; }
    .login-error { background: #fff; border: 1px solid #c3c4c7; border-left: 4px solid #d63638;
        border-radius: 4px; padding: 12px; margin-bottom: 20px; }
    .login-error strong { color: #d63638; }
</style></head>
<body class="login"><div id="login">
    <div class="login-error"><strong>Error:</strong> The username or password you entered is incorrect. <a href="/wp-login.php?action=lostpassword">Lost your password?</a></div>
</div></body></html>'''

    ADMIN_LOGIN_HTML = '''<!DOCTYPE html>
<html><head><title>Admin Panel - Login</title>
<style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
        font-family: "Segoe UI", sans-serif; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
    .card { background: rgba(255,255,255,0.05); backdrop-filter: blur(10px); border: 1px solid rgba(255,255,255,0.1);
        border-radius: 16px; padding: 48px 40px; width: 380px; }
    h2 { color: #fff; margin-bottom: 8px; font-size: 24px; }
    .sub { color: #8892b0; margin-bottom: 32px; font-size: 14px; }
    label { color: #ccd6f6; font-size: 13px; display: block; margin-bottom: 6px; }
    input { width: 100%; padding: 12px 16px; background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.1);
        border-radius: 8px; color: #fff; font-size: 14px; margin-bottom: 20px; outline: none; }
    input:focus { border-color: #64ffda; }
    button { width: 100%; padding: 12px; background: #64ffda; color: #0a192f; border: none;
        border-radius: 8px; font-weight: 600; font-size: 14px; cursor: pointer; }
    button:hover { background: #4cd6b8; }
</style></head>
<body><div class="card">
    <h2>Admin Panel</h2>
    <p class="sub">Sign in to access the control panel</p>
    <form method="post" action="/admin">
        <label>Username</label><input type="text" name="username" required>
        <label>Password</label><input type="password" name="password" required>
        <button type="submit">Sign In</button>
    </form>
</div></body></html>'''

    PMA_LOGIN_HTML = '''<!DOCTYPE html>
<html><head><title>phpMyAdmin</title>
<style>
    body { background: #e7e9ed; font-family: sans-serif; margin: 0; }
    .header { background: #f3d06b; padding: 8px 16px; display: flex; align-items: center; gap: 10px; }
    .header img { height: 24px; }
    .header span { font-weight: bold; font-size: 18px; color: #333; }
    .container { width: 500px; margin: 40px auto; background: #fff; border: 1px solid #ccc; border-radius: 4px; }
    .form-inner { padding: 24px; }
    label { font-size: 14px; color: #333; display: block; margin-bottom: 4px; }
    select, input[type=text], input[type=password] { width: 100%; padding: 6px 8px; margin-bottom: 16px;
        border: 1px solid #aaa; border-radius: 2px; font-size: 14px; }
    .btn { background: #669933; color: #fff; border: 1px solid #5a8a2a; padding: 6px 20px;
        border-radius: 3px; cursor: pointer; font-size: 14px; }
</style></head>
<body>
    <div class="header"><span>phpMyAdmin</span></div>
    <div class="container"><div class="form-inner">
        <form method="post" action="/phpmyadmin">
            <label>Language: <select><option>English</option></select></label>
            <label>Server Choice: <select><option>127.0.0.1</option></select></label>
            <label>Username</label><input type="text" name="pma_username" value="root">
            <label>Password</label><input type="password" name="pma_password">
            <button type="submit" class="btn">Go</button>
        </form>
    </div></div>
</body></html>'''

    JOOMLA_LOGIN_HTML = '''<!DOCTYPE html>
<html><head><title>Joomla! Administrator - Login</title>
<style>
    body { background: #eee; font-family: "Helvetica Neue", sans-serif; }
    .login-box { width: 400px; margin: 80px auto; background: #fff; border-radius: 3px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1); overflow: hidden; }
    .login-header { background: #3d6098; padding: 20px; text-align: center; }
    .login-header h1 { color: #fff; font-size: 20px; margin: 0; }
    .login-body { padding: 30px; }
    .form-group { margin-bottom: 18px; }
    .form-group label { display: block; color: #555; margin-bottom: 5px; font-size: 14px; }
    .form-group input { width: 100%; padding: 10px 12px; border: 1px solid #ccc; border-radius: 3px; font-size: 14px; }
    .btn-primary { width: 100%; background: #3d6098; color: #fff; border: none; padding: 12px;
        border-radius: 3px; font-size: 16px; cursor: pointer; }
    .btn-primary:hover { background: #2c4a7c; }
    .footer { text-align: center; padding: 10px; color: #999; font-size: 12px; }
</style></head>
<body>
    <div class="login-box">
        <div class="login-header"><h1>Joomla! Administration</h1></div>
        <div class="login-body">
            <form method="post" action="/administrator">
                <div class="form-group"><label>Username</label><input type="text" name="username" required></div>
                <div class="form-group"><label>Password</label><input type="password" name="passwd" required></div>
                <button type="submit" class="btn-primary">Log in</button>
            </form>
        </div>
        <div class="footer">Joomla! 3.9.28 Stable</div>
    </div>
</body></html>'''

    DRUPAL_LOGIN_HTML = '''<!DOCTYPE html>
<html><head><title>Log in | Drupal</title>
<style>
    body { background: #f7f7f7; font-family: "Lucida Grande", Verdana, sans-serif; margin: 0; }
    .topbar { background: #0678be; height: 40px; }
    .container { width: 360px; margin: 60px auto; }
    h1 { font-size: 22px; color: #333; margin-bottom: 20px; }
    .form-item { margin-bottom: 16px; }
    .form-item label { display: block; font-size: 14px; color: #333; font-weight: bold; margin-bottom: 4px; }
    .form-item input { width: 100%; padding: 8px; border: 1px solid #b4b4b4; font-size: 14px; border-radius: 2px; }
    .form-submit { background: #0678be; color: #fff; border: none; padding: 8px 24px;
        font-size: 14px; cursor: pointer; border-radius: 2px; font-weight: bold; }
    .form-submit:hover { background: #055c91; }
    .links { margin-top: 16px; }
    .links a { color: #0678be; font-size: 13px; text-decoration: none; }
</style></head>
<body>
    <div class="topbar"></div>
    <div class="container">
        <h1>Log in</h1>
        <form method="post" action="/user/login">
            <div class="form-item"><label>Username</label><input type="text" name="name" required></div>
            <div class="form-item"><label>Password</label><input type="password" name="pass" required></div>
            <input type="submit" class="form-submit" value="Log in">
        </form>
        <div class="links">
            <a href="/user/password">Reset your password</a> |
            <a href="/user/register">Create new account</a>
        </div>
    </div>
</body></html>'''

    ENV_FILE_CONTENT = '''APP_NAME=CompanyApp
APP_ENV=production
APP_KEY=base64:k3J9dG5mR2hKbE1uT3BRclN0VnhZYTJkM2Y0ZzVoNmo=
APP_DEBUG=false
APP_URL=https://app.company-internal.com

DB_CONNECTION=mysql
DB_HOST=db-master.internal
DB_PORT=3306
DB_DATABASE=company_prod
DB_USERNAME=app_user
DB_PASSWORD=Pr0d_S3cret!2024

REDIS_HOST=cache-01.internal
REDIS_PASSWORD=r3d1s_p@ss!
REDIS_PORT=6379

MAIL_MAILER=smtp
MAIL_HOST=smtp.mailgun.org
MAIL_PORT=587
MAIL_USERNAME=postmaster@mg.company.com
MAIL_PASSWORD=mg_s3cret_key_abc123

AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_DEFAULT_REGION=us-east-1
AWS_BUCKET=company-uploads

STRIPE_KEY=pk_live_51H7fake123
STRIPE_SECRET=sk_live_51H7fake456

JWT_SECRET=eyJhbGciOiJIUzI1NiJ9.fake_jwt_secret_do_not_use'''

    ROBOTS_TXT = '''User-agent: *
Disallow: /admin/
Disallow: /administrator/
Disallow: /wp-admin/
Disallow: /phpmyadmin/
Disallow: /api/v1/
Disallow: /backup/
Disallow: /config/
Disallow: /.git/
Disallow: /wp-includes/
Disallow: /server-status

Sitemap: https://www.example.com/sitemap.xml'''

    APACHE_404 = '''<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.41 (Ubuntu) Server at localhost Port 80</address>
</body></html>'''

    APACHE_403 = '''<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<hr>
<address>Apache/2.4.41 (Ubuntu) Server at localhost Port 80</address>
</body></html>'''

    def __init__(self, config):
        super().__init__(config)
        self.fingerprinter = Fingerprinter()
        self.app = web.Application(middlewares=[self._middleware])
        self.runner = None
        self.site = None
        http_conf = self.config.get("honeypot", "http", default={})
        self.port = http_conf.get("port", 8443) if isinstance(http_conf, dict) else 8443
        self.host = http_conf.get("host", "0.0.0.0") if isinstance(http_conf, dict) else "0.0.0.0"
        self.server_header = http_conf.get("server_header", "Apache/2.4.41 (Ubuntu)") if isinstance(http_conf, dict) else "Apache/2.4.41 (Ubuntu)"
        self._setup_routes()

    def _setup_routes(self):
        # WordPress
        self.app.router.add_get('/wp-login.php', self._handle_wp_login)
        self.app.router.add_post('/wp-login.php', self._handle_wp_login_post)
        self.app.router.add_get('/wp-admin', self._handle_wp_redirect)
        self.app.router.add_get('/wp-admin/', self._handle_wp_redirect)
        self.app.router.add_get('/wp-includes/{tail:.*}', self._handle_403)
        self.app.router.add_get('/xmlrpc.php', self._handle_xmlrpc)
        # Admin
        self.app.router.add_get('/admin', self._handle_admin)
        self.app.router.add_post('/admin', self._handle_admin_post)
        # phpMyAdmin
        self.app.router.add_get('/phpmyadmin', self._handle_pma)
        self.app.router.add_post('/phpmyadmin', self._handle_pma_post)
        self.app.router.add_get('/pma', self._handle_pma)
        # Joomla
        self.app.router.add_get('/administrator', self._handle_joomla)
        self.app.router.add_post('/administrator', self._handle_joomla_post)
        # Drupal
        self.app.router.add_get('/user/login', self._handle_drupal)
        self.app.router.add_post('/user/login', self._handle_drupal_post)
        # Sensitive files
        self.app.router.add_get('/.env', self._handle_env)
        self.app.router.add_get('/.git/config', self._handle_git_config)
        self.app.router.add_get('/.git/HEAD', self._handle_git_head)
        self.app.router.add_get('/backup/{tail:.*}', self._handle_backup)
        self.app.router.add_get('/config.php', self._handle_config_php)
        self.app.router.add_get('/server-status', self._handle_server_status)
        # API
        self.app.router.add_get('/api/v1/users', self._handle_api_users)
        self.app.router.add_get('/api/v1/config', self._handle_api_config)
        # Standard
        self.app.router.add_get('/robots.txt', self._handle_robots)
        self.app.router.add_route('*', '/{tail:.*}', self._handle_default)

    @web.middleware
    async def _middleware(self, request, handler):
        ip = request.remote
        ua = request.headers.get('User-Agent', '')
        fingerprint = self.fingerprinter.get_fingerprint(ip, dict(request.headers), ua)
        body_text = ""
        try:
            body_text = await request.text()
        except Exception:
            pass
        self._record_event(
            event_type="http_request", source_ip=ip,
            method=request.method, path=request.path,
            headers=dict(request.headers), query=dict(request.query),
            body=body_text, fingerprint=fingerprint,
        )
        response = await handler(request)
        response.headers['Server'] = self.server_header
        response.headers['X-Powered-By'] = 'PHP/7.4.3'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        return response

    async def start(self):
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, self.host, self.port)
        await self.site.start()
        self._running = True

    async def stop(self):
        if self.runner:
            await self.runner.cleanup()
        self._running = False

    # --- WordPress ---
    async def _handle_wp_login(self, request):
        return web.Response(text=self.WP_LOGIN_HTML, content_type='text/html')

    async def _handle_wp_login_post(self, request):
        data = await request.post()
        self._record_event("http_login_attempt", request.remote,
            target="wordpress", username=data.get('log', ''), password=data.get('pwd', ''))
        return web.Response(text=self.WP_LOGIN_ERROR_HTML, content_type='text/html')

    async def _handle_wp_redirect(self, request):
        raise web.HTTPFound('/wp-login.php?redirect_to=%2Fwp-admin%2F')

    async def _handle_xmlrpc(self, request):
        return web.Response(text='<?xml version="1.0" encoding="UTF-8"?>\n<methodResponse><fault><value><struct><member><name>faultCode</name><value><int>403</int></value></member></struct></value></fault></methodResponse>',
            content_type='text/xml')

    # --- Admin ---
    async def _handle_admin(self, request):
        return web.Response(text=self.ADMIN_LOGIN_HTML, content_type='text/html')

    async def _handle_admin_post(self, request):
        data = await request.post()
        self._record_event("http_login_attempt", request.remote,
            target="admin_panel", username=data.get('username', ''), password=data.get('password', ''))
        return web.Response(text=self.ADMIN_LOGIN_HTML, content_type='text/html')

    # --- phpMyAdmin ---
    async def _handle_pma(self, request):
        return web.Response(text=self.PMA_LOGIN_HTML, content_type='text/html')

    async def _handle_pma_post(self, request):
        data = await request.post()
        self._record_event("http_login_attempt", request.remote,
            target="phpmyadmin", username=data.get('pma_username', ''), password=data.get('pma_password', ''))
        return web.Response(text='#1045 - Access denied for user (using password: YES)', content_type='text/html', status=401)

    # --- Joomla ---
    async def _handle_joomla(self, request):
        return web.Response(text=self.JOOMLA_LOGIN_HTML, content_type='text/html')

    async def _handle_joomla_post(self, request):
        data = await request.post()
        self._record_event("http_login_attempt", request.remote,
            target="joomla", username=data.get('username', ''), password=data.get('passwd', ''))
        return web.Response(text=self.JOOMLA_LOGIN_HTML, content_type='text/html')

    # --- Drupal ---
    async def _handle_drupal(self, request):
        return web.Response(text=self.DRUPAL_LOGIN_HTML, content_type='text/html')

    async def _handle_drupal_post(self, request):
        data = await request.post()
        self._record_event("http_login_attempt", request.remote,
            target="drupal", username=data.get('name', ''), password=data.get('pass', ''))
        return web.Response(text=self.DRUPAL_LOGIN_HTML, content_type='text/html')

    # --- Sensitive Files ---
    async def _handle_env(self, request):
        self._record_event("http_sensitive_file", request.remote, file=".env")
        return web.Response(text=self.ENV_FILE_CONTENT, content_type='text/plain')

    async def _handle_git_config(self, request):
        self._record_event("http_sensitive_file", request.remote, file=".git/config")
        return web.Response(text='[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n[remote "origin"]\n\turl = https://github.com/company/internal-app.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*', content_type='text/plain')

    async def _handle_git_head(self, request):
        self._record_event("http_sensitive_file", request.remote, file=".git/HEAD")
        return web.Response(text='ref: refs/heads/main\n', content_type='text/plain')

    async def _handle_backup(self, request):
        self._record_event("http_sensitive_file", request.remote, file=f"backup/{request.match_info.get('tail', '')}")
        return web.Response(text=self.APACHE_403, content_type='text/html', status=403)

    async def _handle_config_php(self, request):
        self._record_event("http_sensitive_file", request.remote, file="config.php")
        return web.Response(text='<?php\n// Database Configuration\ndefine("DB_HOST", "db-master.internal");\ndefine("DB_USER", "root");\ndefine("DB_PASS", "r00t_p@ssw0rd!");\ndefine("DB_NAME", "production_db");\n?>', content_type='text/plain')

    async def _handle_server_status(self, request):
        self._record_event("http_recon", request.remote, target="server-status")
        return web.Response(text=self.APACHE_403, content_type='text/html', status=403)

    # --- API ---
    async def _handle_api_users(self, request):
        self._record_event("http_api_access", request.remote, endpoint="/api/v1/users")
        return web.json_response({"status": "ok", "data": [
            {"id": 1, "username": "admin", "email": "admin@company.com", "role": "superadmin"},
            {"id": 2, "username": "jdoe", "email": "j.doe@company.com", "role": "editor"},
            {"id": 3, "username": "deploy-bot", "email": "deploy@company.com", "role": "service"},
        ]})

    async def _handle_api_config(self, request):
        self._record_event("http_api_access", request.remote, endpoint="/api/v1/config")
        return web.json_response({"error": "Unauthorized"}, status=401)

    async def _handle_403(self, request):
        return web.Response(text=self.APACHE_403, content_type='text/html', status=403)

    # --- Standard ---
    async def _handle_robots(self, request):
        return web.Response(text=self.ROBOTS_TXT, content_type='text/plain')

    async def _handle_default(self, request):
        return web.Response(text=self.APACHE_404, content_type='text/html', status=404)
