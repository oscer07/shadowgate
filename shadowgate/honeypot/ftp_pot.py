import asyncio
from shadowgate.honeypot.base import BaseHoneypot

class FTPHoneypot(BaseHoneypot):
    PROTOCOL = "ftp"
    
    def __init__(self, config):
        super().__init__(config)
        self.server = None

    async def start(self):
        port = self.config.get("ftp_port", 2121)
        self.server = await asyncio.start_server(self._handle_client, '0.0.0.0', port)
        self._running = True

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        self._running = False

    async def _handle_client(self, reader, writer):
        ip = writer.get_extra_info('peername')[0]
        username = ""
        try:
            writer.write(b"220 (vsFTPd 3.0.3)\r\n")
            await writer.drain()
            while True:
                line = await reader.readline()
                if not line: break
                
                cmd_line = line.decode(errors='replace').strip()
                if not cmd_line: continue
                parts = cmd_line.split(" ", 1)
                cmd = parts[0].upper()
                arg = parts[1] if len(parts) > 1 else ""
                
                self._record_event("ftp_command", ip, command=cmd, argument=arg)
                
                if cmd == "USER":
                    username = arg
                    writer.write(b"331 Please specify the password.\r\n")
                elif cmd == "PASS":
                    self._record_event("ftp_login_attempt", ip, username=username, password=arg)
                    writer.write(b"230 Login successful.\r\n")
                elif cmd == "SYST": writer.write(b"215 UNIX Type: L8\r\n")
                elif cmd == "PWD": writer.write(b'257 "/var/ftp/pub" is the current directory\r\n')
                elif cmd == "LIST":
                    writer.write(b"150 Here comes the directory listing.\r\n226 Directory send OK.\r\n")
                elif cmd in ("TYPE", "PASV", "PORT"): writer.write(b"200 OK.\r\n")
                elif cmd == "QUIT":
                    writer.write(b"221 Goodbye.\r\n")
                    await writer.drain()
                    break
                else: writer.write(b"500 Unknown command.\r\n")
                await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()
