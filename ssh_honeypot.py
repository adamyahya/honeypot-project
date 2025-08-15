import logging
from logging.handlers import RotatingFileHandler
import socket
import paramiko
import threading


# ---------------------------------------------------------------------------
# Logging setup helpers
# ---------------------------------------------------------------------------

def setup_logger(name: str, filename: str) -> logging.Logger:
    """
    Create and configure a rotating log file.
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    handler = RotatingFileHandler(filename, maxBytes=2000, backupCount=5)
    formatter = logging.Formatter(
        '%(asctime)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger


funnel_logger = setup_logger('funnelLogger', 'audits.log')
creds_logger = setup_logger('credsLogger', 'cmd_audits.log')


# ---------------------------------------------------------------------------
#   Global settings
# ---------------------------------------------------------------------------

host_key = paramiko.RSAKey(filename='server.key')
SSH_BANNER = 'SSH-2.0-OpenSSH_7.9'
SHELL_PROMPT = b'corporate-jumpbox2$ '


# ---------------------------------------------------------------------------
#   Emulated shell
# ---------------------------------------------------------------------------

def emulated_shell(channel: paramiko.Channel, client_ip: str):
    # Fake responses for common reconnaissance commands
    command_responses = {
    # Basic system info / recon
    b'pwd': b'/home/corpuser1',
    b'whoami': b'corpuser1',
    b'hostname': b'corp-jumpbox2',
    b'uname -a': b'Linux corp-jumpbox2 5.15.0-105-generic #116-Ubuntu SMP x86_64 GNU/Linux',
    b'id': b'uid=1001(corpuser1) gid=1001(corpuser1) groups=1001(corpuser1)',
    b'ls': b'documents  scripts  jumpbox1.conf',
    b'ls -la': (
        b'drwxr-xr-x 3 corpuser1 corpuser1 4096 Jan 15 10:21 .\n'
        b'drwxr-xr-x 4 root      root      4096 Jan 15 09:55 ..\n'
        b'-rw-r--r-- 1 corpuser1 corpuser1  157 Jan 15 10:21 jumpbox1.conf\n'
        b'drwxr-xr-x 2 corpuser1 corpuser1 4096 Jan 15 09:58 documents\n'
    ),
    b'cat jumpbox1.conf': b'# NOTE: do not edit manually\nendpoint = https://blablabla.com\n',
    b'cat /etc/passwd': (
        b'root:x:0:0:root:/root:/bin/bash\n'
        b'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n'
        b'corpuser1:x:1001:1001::/home/corpuser1:/bin/bash\n'
    ),
    b'netstat -an': (
        b'tcp   0   0 0.0.0.0:22        0.0.0.0:*      LISTEN\n'
        b'tcp   0   0 127.0.0.1:3306    0.0.0.0:*      LISTEN\n'
    ),
    b'ps aux': (
        b'root         1  0.0  0.1  16808  1024 ?        Ss   10:00   0:00 /sbin/init\n'
        b'corpuser1  1021  0.0  0.0  14412   796 pts/0    S+   10:04   0:00 /bin/bash\n'
    ),

    # Network / outbound recon
    b'curl http://example.com/test': b'curl: (7) Failed to connect to example.com port 80: Connection timed out',
    b'wget http://example.com/test': b'--2025--  Resolving example.com ... failed: Name or service not known.',

    # Privilege escalation
    b'sudo -l': (
        b'Matching Defaults entries for corpuser1 on corp-jumpbox2:\n'
        b'    env_reset, mail_badpass, secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n\n'
        b'User corpuser1 may run the following commands on corp-jumpbox2:\n'
        b'    (ALL : ALL) /usr/bin/less\n'
    ),
    b'sudo su': b'[sudo] password for corpuser1: ',
    b'sudo id': b'[sudo] password for corpuser1: ',
}


    channel.send(SHELL_PROMPT)
    command_buffer = b""

    while True:
        data = channel.recv(1024)
        if not data:
            break

        channel.send(data)
        command_buffer += data

        if b'\r' in data:
            command = command_buffer.strip()

            if command == b'exit':
                channel.send(b'Exiting shell...\n')
                break

            response = command_responses.get(command, command)
            creds_logger.info(f"[{client_ip}] executed command: {command.decode()}")

            channel.send(b'\n' + response + b'\r\n')
            channel.send(SHELL_PROMPT)
            command_buffer = b""


# ---------------------------------------------------------------------------
#   Paramiko Server Interface
# ---------------------------------------------------------------------------

class Server(paramiko.ServerInterface):
    def __init__(self, client_ip: str, input_username=None, input_password=None):
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_password = input_password
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        funnel_logger.info(f"Client {self.client_ip} attempted connection with username: {username} password: {password}")
        creds_logger.info(f"{self.client_ip}, {username}, {password}")

        # if credentials specified, enforce them
        if self.input_username and self.input_password:
            return paramiko.AUTH_SUCCESSFUL if (username == self.input_username and password == self.input_password) else paramiko.AUTH_FAILED

        # otherwise, always accept
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True


# ---------------------------------------------------------------------------
#   Client Handler
# ---------------------------------------------------------------------------

def client_handle(client, addr, username, password):
    client_ip = addr[0]
    print(f"[+] Connection from {client_ip}")

    try:
        transport = paramiko.Transport(client)
        transport.local_version = SSH_BANNER
        transport.add_server_key(host_key)

        server = Server(client_ip, username, password)
        transport.start_server(server=server)

        channel = transport.accept(100)
        if channel is None:
            print(f"[-] No channel opened for {client_ip}")
            return

        # Send banner
        banner = "Welcome to Ubuntu 22.04 LTS\r\n\r\n"
        channel.send(banner.encode())

        emulated_shell(channel, client_ip)

    except Exception as e:
        print(f"[!] Exception: {e}")
    finally:
        try:
            transport.close()
        except Exception:
            pass
        client.close()


# ---------------------------------------------------------------------------
#   Honeypot main loop
# ---------------------------------------------------------------------------

def honeypot(address: str, port: int, username=None, password=None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((address, port))
    sock.listen(100)

    print(f"[+] SSH honeypot listening on {address}:{port}")

    while True:
        try:
            client, addr = sock.accept()
            thread = threading.Thread(
                target=client_handle,
                args=(client, addr, username, password),
                daemon=True
            )
            thread.start()

        except Exception as e:
            print(f"[!] Accept failed: {e}")

