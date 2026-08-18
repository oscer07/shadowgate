import asyncio
from shadowgate.honeypot.base import BaseHoneypot

class SSHHoneypot(BaseHoneypot):
    PROTOCOL = "ssh"
    
    def __init__(self, config):
        super().__init__(config)
        self.server = None

    async def start(self):
        port = self.config.get("ssh_port", 2222)
        self.server = await asyncio.start_server(self._handle_client, '0.0.0.0', port)
        self._running = True

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        self._running = False

    async def _handle_client(self, reader, writer):
        ip = writer.get_extra_info('peername')[0]
        try:
            writer.write(b'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1\r\n')
            await writer.drain()
            client_banner = await reader.readline()
            self._record_event("ssh_connect", ip, client_version=client_banner.decode(errors='replace').strip())
            
            writer.write(b'login as: ')
            await writer.drain()
            username = (await reader.readline()).decode(errors='replace').strip()
            
            writer.write(f'{username}@localhost\'s password: '.encode())
            await writer.drain()
            password = (await reader.readline()).decode(errors='replace').strip()
            
            self._record_event("ssh_login_attempt", ip, username=username, password=password)
            
            writer.write(b'\r\nWelcome to Ubuntu 20.04 LTS\r\n')
            while True:
                writer.write(b'admin@server:~$ ')
                await writer.drain()
                cmd = (await reader.readline()).decode(errors='replace').strip()
                if not cmd: continue
                if cmd == 'exit': break
                
                self._record_event("ssh_command", ip, command=cmd)
                
                if cmd == 'ls': writer.write(b'Desktop  Documents  Downloads\r\n')
                elif cmd == 'pwd': writer.write(b'/home/admin\r\n')
                elif cmd == 'whoami': writer.write(b'admin\r\n')
                elif cmd.startswith('cat /etc/passwd'): writer.write(b'root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000::/home/admin:/bin/bash\r\n')
                elif cmd == 'uname -a': writer.write(b'Linux server 5.4.0-42-generic x86_64 GNU/Linux\r\n')
                elif cmd == 'id': writer.write(b'uid=1000(admin) gid=1000(admin) groups=1000(admin)\r\n')
                else: writer.write(f'{cmd.split()[0]}: command not found\r\n'.encode())
                await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()
