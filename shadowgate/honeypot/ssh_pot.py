"""SSH Honeypot — Fake SSH server with interactive shell and session recording."""

import asyncio
import time
import random
from datetime import datetime
from shadowgate.honeypot.base import BaseHoneypot


class SSHHoneypot(BaseHoneypot):
    """SSH honeypot with realistic fake shell and full session recording."""
    
    PROTOCOL = "ssh"
    
    # Fake file system for realistic responses
    FAKE_FILES = {
        "/home/admin": ["Desktop", "Documents", "Downloads", ".bash_history", ".ssh", ".bashrc", ".profile"],
        "/": ["bin", "boot", "dev", "etc", "home", "lib", "lib64", "media", "mnt", "opt", "proc", "root", "run", "sbin", "srv", "sys", "tmp", "usr", "var"],
        "/etc": ["passwd", "shadow", "hosts", "hostname", "resolv.conf", "fstab", "crontab", "sudoers", "ssh"],
        "/var/log": ["syslog", "auth.log", "kern.log", "dmesg", "apache2"],
        "/tmp": [],
    }
    
    FAKE_PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
admin:x:1000:1000:System Admin:/home/admin:/bin/bash
mysql:x:111:117:MySQL Server,,,:/nonexistent:/bin/false
postgres:x:112:118:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash"""
    
    FAKE_SHADOW = """root:$6$rounds=4096$xyz:18923:0:99999:7:::
admin:$6$rounds=4096$abc:18923:0:99999:7:::"""
    
    FAKE_HOSTS = """127.0.0.1\tlocalhost
127.0.1.1\tprod-server-01
10.0.0.1\tdb-master.internal
10.0.0.2\tdb-slave.internal
10.0.0.5\tcache-01.internal
10.0.0.10\tapi-gateway.internal"""
    
    FAKE_CRONTAB = """# m h dom mon dow user command
*/5 * * * * root /opt/scripts/healthcheck.sh
0 2 * * * root /usr/bin/certbot renew --quiet
0 3 * * 0 root /opt/backup/backup.sh
*/10 * * * * admin /opt/monitor/check_services.py"""
    
    FAKE_BASHRC = """# ~/.bashrc: executed by bash for non-login shells.
export PATH=$PATH:/opt/scripts
export EDITOR=vim
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
# Custom aliases
alias deploy='/opt/deploy/deploy.sh'
alias dbconn='mysql -h db-master.internal -u admin -p'"""
    
    FAKE_PROCESSES = """  PID TTY      STAT   TIME COMMAND
    1 ?        Ss     0:03 /sbin/init
  234 ?        Ss     0:01 /usr/sbin/sshd -D
  456 ?        Ssl    0:12 /usr/sbin/mysqld
  512 ?        Ss     0:02 /usr/sbin/apache2 -k start
  678 ?        S      0:00 /usr/sbin/apache2 -k start
  679 ?        S      0:00 /usr/sbin/apache2 -k start
  890 ?        Ssl    0:08 /usr/bin/python3 /opt/app/server.py
  912 ?        S      0:00 /usr/sbin/cron -f
 1001 pts/0    Ss     0:00 -bash
 1045 pts/0    R+     0:00 ps aux"""

    def __init__(self, config):
        super().__init__(config)
        self.server = None
        self.sessions: dict = {}  # ip -> session data
        ssh_conf = self.config.get("honeypot", "ssh", default={})
        self.port = ssh_conf.get("port", 2222) if isinstance(ssh_conf, dict) else 2222
        self.host = ssh_conf.get("host", "0.0.0.0") if isinstance(ssh_conf, dict) else "0.0.0.0"
        self.banner = ssh_conf.get("server_version", "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5") if isinstance(ssh_conf, dict) else "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
        self.fake_hostname = ssh_conf.get("fake_hostname", "prod-server-01") if isinstance(ssh_conf, dict) else "prod-server-01"

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
        cwd = "/home/admin"
        username = "admin"
        env_vars = {
            "HOME": "/home/admin",
            "USER": "admin",
            "SHELL": "/bin/bash",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "en_US.UTF-8",
            "TERM": "xterm-256color",
            "HOSTNAME": self.fake_hostname,
        }
        
        try:
            # SSH banner exchange
            writer.write(f"{self.banner}\r\n".encode())
            await writer.drain()
            client_banner = await asyncio.wait_for(reader.readline(), timeout=30)
            client_version = client_banner.decode(errors='replace').strip()
            self._record_event("ssh_connect", ip, client_version=client_version)
            session_log.append(f"[CONNECT] client={client_version}")

            # Authentication
            writer.write(b"login as: ")
            await writer.drain()
            username = (await asyncio.wait_for(reader.readline(), timeout=60)).decode(errors='replace').strip()
            env_vars["USER"] = username

            writer.write(f"{username}@{self.fake_hostname}'s password: ".encode())
            await writer.drain()
            password = (await asyncio.wait_for(reader.readline(), timeout=60)).decode(errors='replace').strip()

            self._record_event("ssh_login_attempt", ip, username=username, password=password)
            session_log.append(f"[AUTH] user={username} pass={password}")

            # Welcome banner
            welcome = (
                f"\r\nWelcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-167-generic x86_64)\r\n"
                f"\r\n * Documentation:  https://help.ubuntu.com\r\n"
                f" * Management:     https://landscape.canonical.com\r\n"
                f" * Support:        https://ubuntu.com/advantage\r\n"
                f"\r\n  System information as of {datetime.utcnow().strftime('%a %b %d %H:%M:%S UTC %Y')}\r\n"
                f"\r\n  System load:  0.{random.randint(10,89)}  Processes:           {random.randint(120,250)}\r\n"
                f"  Usage of /:   {random.randint(30,75)}% of 49.15GB   Users logged in:     1\r\n"
                f"  Memory usage: {random.randint(40,80)}%              IPv4 address for eth0: 10.0.0.{random.randint(10,200)}\r\n"
                f"  Swap usage:   {random.randint(0,15)}%\r\n"
                f"\r\nLast login: {datetime.utcnow().strftime('%a %b %d %H:%M:%S %Y')} from {ip}\r\n"
            )
            writer.write(welcome.encode())
            await writer.drain()

            # Interactive shell loop
            while True:
                prompt = f"{username}@{self.fake_hostname}:{cwd}$ "
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
                self._record_event("ssh_command", ip, command=cmd, username=username)
                
                output = self._execute_command(cmd, cwd, username, env_vars)
                
                if output is None:  # exit command
                    writer.write(b"logout\r\nConnection to server closed.\r\n")
                    await writer.drain()
                    break
                
                if isinstance(output, dict) and "new_cwd" in output:
                    cwd = output["new_cwd"]
                    output = output.get("output", "")
                    
                if output:
                    writer.write(output.encode() if isinstance(output, str) else output)
                    await writer.drain()

        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
            pass
        except Exception:
            pass
        finally:
            duration = round(time.time() - session_start, 2)
            self._record_event(
                "ssh_session_complete", ip,
                username=username,
                duration_seconds=duration,
                commands_count=len([l for l in session_log if l.startswith("[CMD]")]),
                session_log=session_log,
            )
            try:
                writer.close()
            except Exception:
                pass

    def _execute_command(self, cmd: str, cwd: str, username: str, env: dict):
        """Execute a fake shell command and return output."""
        parts = cmd.split()
        base_cmd = parts[0] if parts else ""
        args = parts[1:] if len(parts) > 1 else []
        
        # ---- Navigation ----
        if base_cmd == "cd":
            target = args[0] if args else "/home/admin"
            if target == "~":
                target = "/home/admin"
            elif target == "..":
                target = "/".join(cwd.rstrip("/").split("/")[:-1]) or "/"
            elif not target.startswith("/"):
                target = f"{cwd.rstrip('/')}/{target}"
            if target in self.FAKE_FILES or target in ("/home/admin", "/root", "/tmp"):
                return {"new_cwd": target, "output": ""}
            return f"bash: cd: {target}: No such file or directory\r\n"
        
        if base_cmd == "exit" or base_cmd == "logout":
            return None
            
        # ---- File system ----
        if base_cmd == "ls":
            show_all = "-a" in args or "-la" in args or "-al" in args or "-lah" in args
            show_long = "-l" in args or "-la" in args or "-al" in args or "-lah" in args
            target_dir = cwd
            for a in args:
                if not a.startswith("-"):
                    target_dir = a if a.startswith("/") else f"{cwd.rstrip('/')}/{a}"
                    break
            files = self.FAKE_FILES.get(target_dir, self.FAKE_FILES.get(cwd, []))
            if show_all:
                files = [".", ".."] + files
            if show_long:
                lines = [f"total {len(files) * 4}"]
                for f in files:
                    is_dir = not "." in f or f in (".", "..", ".ssh")
                    perm = "drwxr-xr-x" if is_dir else "-rw-r--r--"
                    size = random.randint(100, 8192) if not is_dir else 4096
                    date = "Jan 15 09:23"
                    lines.append(f"{perm}  1 {username} {username} {size:>6} {date} {f}")
                return "\r\n".join(lines) + "\r\n"
            return "  ".join(files) + "\r\n" if files else "\r\n"
            
        if base_cmd == "pwd":
            return f"{cwd}\r\n"
            
        if base_cmd == "cat":
            target = args[0] if args else ""
            if "passwd" in target:
                return self.FAKE_PASSWD + "\r\n"
            elif "shadow" in target:
                return self.FAKE_SHADOW + "\r\n"
            elif "hosts" in target:
                return self.FAKE_HOSTS + "\r\n"
            elif "crontab" in target:
                return self.FAKE_CRONTAB + "\r\n"
            elif ".bashrc" in target:
                return self.FAKE_BASHRC + "\r\n"
            elif ".bash_history" in target:
                return "mysql -u root -p\ncd /opt/app\npython3 server.py\nls -la /var/backups\nscp backup.tar.gz admin@10.0.0.5:/backups/\r\n"
            elif target:
                return f"cat: {target}: No such file or directory\r\n"
            return ""
            
        # ---- System info ----
        if base_cmd == "whoami":
            return f"{username}\r\n"
        if base_cmd == "id":
            uid = 0 if username == "root" else 1000
            return f"uid={uid}({username}) gid={uid}({username}) groups={uid}({username}),4(adm),24(cdrom),27(sudo),30(dip)\r\n"
        if base_cmd == "uname":
            if "-a" in args:
                return f"Linux {env.get('HOSTNAME', 'server')} 5.4.0-167-generic #184-Ubuntu SMP Tue Oct 31 09:21:49 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\r\n"
            if "-r" in args:
                return "5.4.0-167-generic\r\n"
            return "Linux\r\n"
        if base_cmd == "hostname":
            return f"{env.get('HOSTNAME', 'server')}\r\n"
        if base_cmd == "uptime":
            days = random.randint(10, 365)
            hours = random.randint(0, 23)
            return f" {datetime.utcnow().strftime('%H:%M:%S')} up {days} days, {hours}:{random.randint(0,59):02d},  1 user,  load average: 0.{random.randint(10,99)}, 0.{random.randint(10,99)}, 0.{random.randint(10,99)}\r\n"
        if base_cmd == "date":
            return f"{datetime.utcnow().strftime('%a %b %d %H:%M:%S UTC %Y')}\r\n"
        
        # ---- Process & Network ----
        if base_cmd == "ps":
            return self.FAKE_PROCESSES + "\r\n"
        if base_cmd in ("netstat", "ss"):
            return (
                "Active Internet connections (servers and established)\r\n"
                "Proto Recv-Q Send-Q Local Address           Foreign Address         State\r\n"
                "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\r\n"
                "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\r\n"
                "tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN\r\n"
                "tcp        0      0 0.0.0.0:3306            0.0.0.0:*               LISTEN\r\n"
                f"tcp        0    308 10.0.0.42:22            {env.get('HOSTNAME', '10.0.0.1')}:54321    ESTABLISHED\r\n"
            )
        if base_cmd == "ifconfig" or (base_cmd == "ip" and args and args[0] == "addr"):
            return (
                "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n"
                f"        inet 10.0.0.{random.randint(10,200)}  netmask 255.255.255.0  broadcast 10.0.0.255\r\n"
                "        inet6 fe80::a00:27ff:fe8d:c04d  prefixlen 64  scopeid 0x20<link>\r\n"
                "        ether 08:00:27:8d:c0:4d  txqueuelen 1000  (Ethernet)\r\n"
                "        RX packets 1524673  bytes 389424117 (371.4 MiB)\r\n"
                "        TX packets 897241  bytes 132847293 (126.6 MiB)\r\n"
            )
        
        # ---- Disk & Memory ----
        if base_cmd == "df":
            return (
                "Filesystem      Size  Used Avail Use% Mounted on\r\n"
                "udev            3.9G     0  3.9G   0% /dev\r\n"
                "tmpfs           798M  1.6M  796M   1% /run\r\n"
                f"/dev/sda1        49G   {random.randint(15,35)}G   {random.randint(10,30)}G  {random.randint(35,75)}% /\r\n"
                "tmpfs           3.9G     0  3.9G   0% /dev/shm\r\n"
            )
        if base_cmd == "free":
            total = 8192
            used = random.randint(3000, 6000)
            return (
                "              total        used        free      shared  buff/cache   available\r\n"
                f"Mem:          {total}        {used}        {total-used-1024}         128        1024        {total-used}\r\n"
                f"Swap:         2048         {random.randint(0, 300)}        {random.randint(1700, 2048)}\r\n"
            )
        
        # ---- Network tools (logged as suspicious) ----
        if base_cmd in ("wget", "curl"):
            url = args[0] if args else "http://example.com"
            self._record_event("ssh_download_attempt", env.get("HOSTNAME", "unknown"), command=cmd, url=url)
            if base_cmd == "wget":
                return f"--{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}--  {url}\r\nResolving... failed: Name or service not known.\r\nwget: unable to resolve host address\r\n"
            return f"curl: (6) Could not resolve host: {url.replace('http://', '').replace('https://', '').split('/')[0]}\r\n"
            
        if base_cmd == "ping":
            host = args[0] if args else "localhost"
            return f"PING {host} (127.0.0.1) 56(84) bytes of data.\r\n64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.{random.randint(10,99)} ms\r\n\r\n--- {host} ping statistics ---\r\n1 packets transmitted, 1 received, 0% packet loss\r\n"
        
        # ---- Other commands ----
        if base_cmd == "echo":
            text = " ".join(args)
            # Check for env var expansion
            for var_name, var_val in env.items():
                text = text.replace(f"${var_name}", var_val)
            return f"{text}\r\n"
        if base_cmd == "env" or base_cmd == "printenv":
            return "\r\n".join(f"{k}={v}" for k, v in env.items()) + "\r\n"
        if base_cmd == "history":
            return "    1  ls -la\r\n    2  cd /opt/app\r\n    3  python3 server.py\r\n    4  mysql -u root -p\r\n    5  cat /etc/passwd\r\n    6  netstat -tlnp\r\n    7  df -h\r\n    8  free -m\r\n"
        if base_cmd == "w" or base_cmd == "who":
            return f"{username}  pts/0    {datetime.utcnow().strftime('%H:%M')}   0.00s  0.00s  -bash\r\n"
        if base_cmd == "last":
            return f"{username}  pts/0    10.0.0.1  {datetime.utcnow().strftime('%a %b %d %H:%M')}   still logged in\r\n"
        if base_cmd == "sudo":
            return f"[sudo] password for {username}: \r\nSorry, try again.\r\n"
        if base_cmd == "su":
            return "Password: \r\nsu: Authentication failure\r\n"
        if base_cmd == "chmod" or base_cmd == "chown" or base_cmd == "mkdir" or base_cmd == "touch":
            return ""  # Silently "succeed"
        if base_cmd == "rm":
            return ""  # Silently "succeed" 
        if base_cmd == "cp" or base_cmd == "mv":
            return ""
        if base_cmd == "head" or base_cmd == "tail":
            return ""  # Empty output
        if base_cmd == "grep":
            return ""  # No matches
        if base_cmd == "find":
            return ""  # No results
        if base_cmd == "which":
            target = args[0] if args else ""
            if target in ("python3", "python", "bash", "ls", "cat", "ssh", "scp", "mysql", "wget", "curl"):
                return f"/usr/bin/{target}\r\n"
            return f"{target} not found\r\n"
        if base_cmd in ("vi", "vim", "nano"):
            return f"Error opening terminal: {env.get('TERM', 'unknown')}.\r\n"
        if base_cmd == "clear":
            return "\033[2J\033[H"  # ANSI clear screen
        if base_cmd == "help":
            return "GNU bash, version 5.0.17(1)-release (x86_64-pc-linux-gnu)\r\nType 'help name' for information on builtin commands.\r\n"
        if base_cmd == "export":
            if args:
                kv = args[0].split("=", 1)
                if len(kv) == 2:
                    env[kv[0]] = kv[1]
            return ""
        if base_cmd == "unset":
            if args and args[0] in env:
                del env[args[0]]
            return ""
        if base_cmd in ("service", "systemctl"):
            return "Failed to connect to bus: No such file or directory\r\n"
        if base_cmd == "crontab":
            if "-l" in args:
                return self.FAKE_CRONTAB + "\r\n"
            return ""
        if base_cmd == "scp":
            self._record_event("ssh_file_transfer_attempt", env.get("HOSTNAME", "unknown"), command=cmd)
            return "ssh: connect to host: Connection refused\r\n"
        if base_cmd == "ssh":
            self._record_event("ssh_lateral_movement", env.get("HOSTNAME", "unknown"), command=cmd)
            return "ssh: connect to host: Connection refused\r\n"
        if base_cmd in ("mysql", "psql", "mongo", "redis-cli"):
            self._record_event("ssh_db_access_attempt", env.get("HOSTNAME", "unknown"), command=cmd)
            return f"{base_cmd}: command not found\r\n"
        if base_cmd == "docker":
            return "Got permission denied while trying to connect to the Docker daemon socket\r\n"
        if base_cmd == "apt" or base_cmd == "apt-get" or base_cmd == "yum":
            return f"E: Could not open lock file - open (13: Permission denied)\r\n"
        
        # Default: command not found
        return f"bash: {base_cmd}: command not found\r\n"
