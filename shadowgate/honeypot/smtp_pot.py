import asyncio
from shadowgate.honeypot.base import BaseHoneypot

class SMTPHoneypot(BaseHoneypot):
    PROTOCOL = "smtp"
    
    def __init__(self, config):
        super().__init__(config)
        self.server = None

    async def start(self):
        port = self.config.get("smtp_port", 2525)
        self.server = await asyncio.start_server(self._handle_client, '0.0.0.0', port)
        self._running = True

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        self._running = False

    async def _handle_client(self, reader, writer):
        ip = writer.get_extra_info('peername')[0]
        in_data = False
        data_buffer = []
        mail_from, rcpt_to = "", []
        try:
            writer.write(b"220 mail.localdomain ESMTP Postfix\r\n")
            await writer.drain()
            while True:
                line = await reader.readline()
                if not line: break
                stripped = line.decode(errors='replace').strip()
                
                if in_data:
                    if stripped == ".":
                        in_data = False
                        self._record_event("smtp_message", ip, mail_from=mail_from, rcpt_to=rcpt_to, body="\n".join(data_buffer))
                        writer.write(b"250 2.0.0 Ok: queued as 123456789\r\n")
                        data_buffer, mail_from, rcpt_to = [], "", []
                    else:
                        data_buffer.append(stripped)
                    await writer.drain()
                    continue
                
                if not stripped: continue
                parts = stripped.split(" ", 1)
                cmd = parts[0].upper()
                arg = parts[1] if len(parts) > 1 else ""
                
                self._record_event("smtp_command", ip, command=cmd, argument=arg)
                
                if cmd in ("HELO", "EHLO"): writer.write(b"250-mail.localdomain\r\n250-PIPELINING\r\n250 DSN\r\n")
                elif cmd == "MAIL":
                    mail_from = arg
                    writer.write(b"250 2.1.0 Ok\r\n")
                elif cmd == "RCPT":
                    rcpt_to.append(arg)
                    writer.write(b"250 2.1.5 Ok\r\n")
                elif cmd == "DATA":
                    in_data = True
                    writer.write(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                elif cmd in ("RSET", "NOOP"): writer.write(b"250 2.0.0 Ok\r\n")
                elif cmd == "VRFY": writer.write(b"252 2.0.0 Send some mail, I'll try my best\r\n")
                elif cmd == "QUIT":
                    writer.write(b"221 2.0.0 Bye\r\n")
                    await writer.drain()
                    break
                else: writer.write(b"502 5.5.2 Error: command not recognized\r\n")
                await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()
