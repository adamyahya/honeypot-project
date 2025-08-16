"""
Honeypy — Command-line launcher for the SSH and HTTP honeypots.

Only one honeypot can be launched at a time (SSH OR HTTP).
"""

import argparse
from ssh_honeypot import honeypot as run_ssh_honeypot
from web_honeypot import run_web_honeypot


def main():
    """Parse CLI arguments and start the appropriate honeypot."""
    parser = argparse.ArgumentParser(
        description="Honeypy — SSH & HTTP Honeypot Launcher"
    )
    parser.add_argument(
        "-a", "--address", type=str, required=True,
        help="IP address to bind the honeypot"
    )
    parser.add_argument(
        "-p", "--port", type=int, required=True,
        help="Port to listen on"
    )
    parser.add_argument(
        "-u", "--username", type=str, default=None,
        help="Optional username to enforce"
    )
    parser.add_argument(
        "-pw", "--password", type=str, default=None,
        help="Optional password to enforce"
    )
    parser.add_argument(
        "-s", "--ssh", action="store_true",
        help="Run SSH honeypot"
    )
    parser.add_argument(
        "-w", "--http", action="store_true",
        help="Run HTTP/WordPress honeypot"
    )

    args = parser.parse_args()

    try:
        if args.ssh:
            # SSH honeypot
            print(f"[-] Running SSH Honeypot on {args.address}:{args.port} ...")
            run_ssh_honeypot(
                address=args.address,
                port=args.port,
                username=args.username,
                password=args.password
            )

        elif args.http:
            # HTTP (WordPress) honeypot
            username = args.username or "admin"
            password = args.password or "password"
            print(f"[-] Running HTTP Honeypot on port {args.port} ...")
            print(f"    Username: {username} | Password: {password}")
            run_web_honeypot(port=args.port, username=username, password=password)

        else:
            print("[!] Please choose a honeypot type: SSH (--ssh) or HTTP (--http)")

    except KeyboardInterrupt:
        print("\n[!] Honeypot stopped by user. Exiting...")
    except Exception as error:
        print(f"\n[!] Unexpected error: {error}")


if __name__ == "__main__":
    main()
