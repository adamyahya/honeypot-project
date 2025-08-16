"""
SSH Honeypot module — emulates SSH server and fake shell to log
credentials and basic command execution attempts.
"""

import socket
import threading
import logging
from logging.handlers import RotatingFileHandler
import paramiko

# ----- Logging setup -------------------------------------------------------

def setup_logger(name: str, filename: str) -> logging.Logger:
    """Create and configure a rotating log file."""
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    handler = RotatingFileHandler(filename, maxBytes=2000, backupCount=5)
    formatter = logging.Formatter(
        "%(asctime)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


funnel_logger = setup_logger("funnelLogger", "audits.log")
creds_logger = setup_logger("credsLogger", "cmd_audits.log")

# ----- Global settings -----------------------------------------------------

HOST_KEY = paramiko.RSAKey(filename="server.key")
SSH_BANNER = "SSH-2.0-OpenSSH_7.9"
SHELL_PROMPT = b"corporate-jumpbox2$ "

# ----- Shell emulation logic ----------------------------------------------

COMMAND_RESPONSES = {
    b"pwd": b"/home/corpuser1",
    b"whoami": b"corpuser1",
    b"hostname": b"corp-jumpbox2",
    b"uname -a": (
        b"Linux corp-jumpbox2 5.15.0-105-generic #116-Ubuntu SMP x86_64 GNU/Linux"
    ),
    b"id": (
        b"uid=1001(corpuser1) gid=1001(corpuser1)"
        b" groups=1001(corpuser1)"
    ),
    b"ls": b"documents  scripts  jumpbox1.conf",
    b"ls -la": (
        b"drwxr-xr-x 3 corpuser1 corpuser1 4096 Jan 15 10:21 .\n"
        b"drwxr-xr-x 4 root      root      4096 Jan 15 09:55 ..\n"
        b"-rw-r--r-- 1 corpuser1 corpuser1  157 Jan 15 10:21 jumpbox1.conf\n"
        b"drwxr-xr-x 2 corpuser1 corpuser1 4096 Jan 15 09:58 documents"
    ),
    b"cat jumpbox1.conf": (
        b"# NOTE: do not edit manually\nendpoint = https://blablabla.com"
    ),
    b"cat /etc/passwd": (
        b"root:x:0:0:root:/root:/bin/bash\n"
        b"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        b"corpuser1:x:1001:1001::/home/corpuser1:/bin/bash"
    ),
    b"netstat -an": (
        b"tcp   0   0 0.0.0.0:22        0.0.0.0:*      LISTEN\n"
        b"tcp   0   0 127.0.0.1:3306    0.0.0.0:*      LISTEN"
    ),
    b"ps aux": (
        b"root         1  0.0  0.1  16808  1024 ?        Ss   10:00   0:00 /sbin/init\n"
        b"corpuser1  1021  0.0  0.0  14412   796 pts/0    S+   10:04   0:00 /bin/bash"
    ),
    b"curl http://example.com/test": (
        b"curl: (7) Failed to connect to example.com port 80: Connection timed out"
    ),
    b"wget http://example.com/test": (
        b"--2025--  Resolving example.com ... failed: Name or service not known."
    ),
    b"sudo -l": (
        b"Matching Defaults entries for corpuser1 on corp-jumpbox2:\n"
        b"env_reset, mail_badpass,secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n\n"
        b"User corpuser1 may run the following commands on corp-jumpbox2:\n"
        b"(ALL : ALL) /usr/bin/less"
    ),
    b"sudo su": b"[sudo] password for corpuser1: ",
    b"sudo id": b"[sudo] password for corpuser1: ",
}


def emulated_shell(channel: paramiko.Channel, client_ip: str) -> None:
    """Fake shell that receives a command and returns a predefined response."""
    channel.send(SHELL_PROMPT)
    command_buffer = b""

    while True:
        data = channel.recv(1024)
        if not data:
            break

        channel.send(data)
        command_buffer += data

        if b"\r" in data:
            command = command_buffer.strip()
            if command == b"exit":
                channel.send(b"Exiting shell...\n")
                break

            # Look up the response or echo the command itself
            response = COMMAND_RESPONSES.get(command, command)
            creds_logger.info(
                "[%s] executed command: %s",
                client_ip,
                command.decode()
            )

            channel.send(b"\n" + response + b"\r\n")
            channel.send(SHELL_PROMPT)
            command_buffer = b""


# ----- Paramiko server interface ------------------------------------------

class Server(paramiko.ServerInterface):
    """Paramiko-based server interface used for the honeypot."""

    def __init__(self, client_ip: str, input_username=None, input_password=None):
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_password = input_password
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else None

    def get_allowed_auths(self, username=None):
        return "password"

    def check_auth_password(self, username, password):
        # Log all credentials
        funnel_logger.info(
            "Client %s attempted connection with username: %s password: %s",
            self.client_ip, username, password
        )

        # If credentials are enforced, accept only matching values
        if self.input_username and self.input_password:
            return (
                paramiko.AUTH_SUCCESSFUL
                if (username == self.input_username and password == self.input_password)
                else paramiko.AUTH_FAILED
            )

        # Otherwise always accept
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True


# ----- Connection handler --------------------------------------------------

def client_handle(client, addr, username=None, password=None) -> None:
    """Handle an incoming SSH client, start fake shell session."""
    client_ip = addr[0]
    print(f"[+] Connection from {client_ip}")

    try:
        transport = paramiko.Transport(client)
        transport.local_version = SSH_BANNER
        transport.add_server_key(HOST_KEY)
        server = Server(client_ip, username, password)
        transport.start_server(server=server)

        channel = transport.accept(20)
        if channel is None:
            print(f"[-] No channel opened for {client_ip}")
            return

        channel.send(b"Welcome to Ubuntu 22.04 LTS\r\n\r\n")
        emulated_shell(channel, client_ip)

    except paramiko.SSHException as error:
        funnel_logger.error("SSH error: %s", error)

    finally:
        try:
            transport.close()
        except Exception:
            pass
        client.close()


# ----- Honeypot main loop -------------------------------------------------

def honeypot(address: str, port: int, username=None, password=None) -> None:
    """Start the SSH honeypot and accept connections."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((address, port))
    server_socket.listen(100)

    print(f"[+] SSH honeypot listening on {address}:{port}")

    while True:
        try:
            client, addr = server_socket.accept()
            thread = threading.Thread(
                target=client_handle,
                args=(client, addr, username, password),
                daemon=True
            )
            thread.start()

        except OSError as error:
            funnel_logger.error("Socket error: %s", error)
