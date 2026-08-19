"""Telnet Honeypot — Fake Telnet server with session recording."""

import asyncio
import time
from datetime import datetime
from shadowgate.honeypot.base import BaseHoneypot


class TelnetHoneypot(BaseHoneypot):
    """Telnet honeypot emulating a vulnerable IoT/router device."""

    PROTOCOL = "telnet"

    # Common IoT/router default credentials that attackers try
    ALLOWED_CREDS = [
        ("admin", "admin"), ("root", "root"), ("admin", "password"),
        ("root", ""), ("admin", "1234"), ("user", "user"),
    ]

    def __init__(self, config):
        super().__init__(config)
        self.server = None
        telnet_conf = self.config.get("honeypot", "telnet", default={})
        self.port = telnet_conf.get("port", 2323) if isinstance(telnet_conf, dict) else 2323
        self.host = telnet_conf.get("host", "0.0.0.0") if isinstance(telnet_conf, dict) else "0.0.0.0"
        self.banner = telnet_conf.get("banner", "BusyBox v1.30.1 (Ubuntu 20.04)") if isinstance(telnet_conf, dict) else "BusyBox v1.30.1 (Ubuntu 20.04)"
        self.max_attempts = 3

    async def start(self):
        self.server = await asyncio.start_server(
            self._handle_client, self.host, self.port
        )
        self._running = True

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        self._running = False

    async def _handle_client(self, reader, writer):
        ip = writer.get_extra_info('peername')[0]
        session_start = time.time()
        session_log = []
        username = ""

        try:
            self._record_event("telnet_connect", ip)
            session_log.append(f"[CONNECT] from {ip}")

            # Banner
            writer.write(f"\r\n{self.banner}\r\n\r\n".encode())
            await writer.drain()

            # Authentication loop
            authenticated = False
            for attempt in range(self.max_attempts):
                writer.write(b"login: ")
                await writer.drain()
                username = (await asyncio.wait_for(reader.readline(), timeout=60)).decode(errors='replace').strip()

                writer.write(b"Password: ")
                await writer.drain()
                password = (await asyncio.wait_for(reader.readline(), timeout=60)).decode(errors='replace').strip()

                self._record_event("telnet_login_attempt", ip,
                    username=username, password=password, attempt=attempt + 1)
                session_log.append(f"[AUTH] user={username} pass={password}")

                # Accept common default creds to lure attacker deeper
                if (username, password) in self.ALLOWED_CREDS or attempt >= self.max_attempts - 1:
                    authenticated = True
                    break
                else:
                    writer.write(b"\r\nLogin incorrect\r\n\r\n")
                    await writer.drain()

            if not authenticated:
                writer.write(b"\r\nToo many login failures. Connection closed.\r\n")
                await writer.drain()
                return

            # Shell
            writer.write(f"\r\n\r\nBusyBox v1.30.1 built-in shell (ash)\r\n\r\n".encode())
            await writer.drain()

            while True:
                prompt = f"{username}@gateway:~# " if username == "root" else f"{username}@gateway:~$ "
                writer.write(prompt.encode())
                await writer.drain()

                try:
                    raw = await asyncio.wait_for(reader.readline(), timeout=300)
                except asyncio.TimeoutError:
                    break

                if not raw:
                    break

                cmd = raw.decode(errors='replace').strip()
                if not cmd:
                    continue

                session_log.append(f"[CMD] {cmd}")
                self._record_event("telnet_command", ip, command=cmd, username=username)

                output = self._run_command(cmd, username)
                if output is None:
                    break
                if output:
                    writer.write(output.encode())
                    await writer.drain()

        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
            pass
        except Exception:
            pass
        finally:
            duration = round(time.time() - session_start, 2)
            self._record_event("telnet_session_complete", ip,
                username=username, duration_seconds=duration,
                commands_count=len([l for l in session_log if l.startswith("[CMD]")]),
                session_log=session_log)
            try:
                writer.close()
            except Exception:
                pass

    def _run_command(self, cmd: str, username: str):
        """Execute fake BusyBox-style commands."""
        parts = cmd.split()
        base = parts[0] if parts else ""
        args = parts[1:] if len(parts) > 1 else []

        if base in ("exit", "logout", "quit"):
            return None
        if base == "ls":
            return "bin     dev     etc     lib     mnt     proc    sys     usr\r\nboot    home    media   opt     root    sbin    tmp     var\r\n"
        if base == "pwd":
            return f"/{'root' if username == 'root' else 'home/' + username}\r\n"
        if base == "whoami":
            return f"{username}\r\n"
        if base == "id":
            uid = 0 if username == "root" else 1000
            return f"uid={uid}({username}) gid={uid}({username})\r\n"
        if base == "uname":
            return "Linux gateway 4.15.0-generic armv7l GNU/Linux\r\n" if "-a" in args else "Linux\r\n"
        if base == "cat":
            if args and "passwd" in args[0]:
                return "root:x:0:0:root:/root:/bin/ash\r\nnobody:x:65534:65534:nobody:/nonexistent:/bin/false\r\nadmin:x:1000:1000:Admin:/home/admin:/bin/ash\r\n"
            return f"cat: can't open '{args[0] if args else ''}': No such file or directory\r\n"
        if base == "ps":
            return "  PID USER       VSZ STAT COMMAND\r\n    1 root      1200 S    init\r\n   89 root      1500 S    /usr/sbin/telnetd\r\n  112 root       900 S    /usr/sbin/httpd\r\n  156 root       800 S    /usr/sbin/crond\r\n"
        if base in ("wget", "curl", "tftp"):
            self._record_event("telnet_download_attempt", "gateway", command=cmd)
            return f"{base}: can't connect to remote host: Connection refused\r\n"
        if base == "busybox":
            return "BusyBox v1.30.1 () multi-call binary.\r\nUsage: busybox [function [arguments]...]\r\n"
        if base == "enable" or base == "system" or base == "shell" or base == "sh":
            return f"{username}@gateway:~# \r\n"
        if base == "echo":
            return " ".join(args) + "\r\n"
        if base == "help":
            return "Built-in commands: cat cd echo exit help ls pwd uname whoami\r\n"
        if base == "cd":
            return ""
        if base == "ifconfig":
            return "eth0      Link encap:Ethernet  HWaddr 00:1A:2B:3C:4D:5E\r\n          inet addr:192.168.1.1  Bcast:192.168.1.255  Mask:255.255.255.0\r\n          UP BROADCAST RUNNING MULTICAST  MTU:1500\r\n"
        if base == "reboot" or base == "shutdown":
            self._record_event("telnet_destructive_command", "gateway", command=cmd)
            return ""

        return f"-ash: {base}: not found\r\n"
