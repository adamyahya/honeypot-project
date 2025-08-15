# Honeypot Project

This project is a **dual honeypot system** designed for **educational and testing purposes**.  
It simulates both **SSH** and **WordPress HTTP login services** to capture attack attempts safely in an isolated environment.

---

## Features

### SSH Honeypot
- Captures SSH login attempts.
- Emulates a fake shell with commands like:
  - `pwd`
  - `whoami`
  - `ls`
  - `cat <filename>`
- Logs credentials and commands to `cmd_audits.log`.

### HTTP/WordPress Honeypot
- Fake WordPress login page (`wp-admin.html`).
- Captures login attempts.
- Displays a fake admin dashboard (`admin.html`) on successful login.
- Logs credentials to `http_audits.log`.
Usage
Run SSH Honeypot
python honeypy.py --ssh --address 0.0.0.0 --port 2222


Optional: specify username and password

python honeypy.py --ssh --address 0.0.0.0 --port 2222 --username corpuser --password test123

Run HTTP/WordPress Honeypot
python honeypy.py --http --address 0.0.0.0 --port 5000
