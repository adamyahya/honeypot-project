import argparse
from ssh_honeypot import honeypot as run_ssh_honeypot
from web_honeypot import run_web_honeypot

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Honeypy — SSH & HTTP Honeypot Launcher")
    parser.add_argument(
    '-a', '--address', type=str, required=True, help="IP address to bind the honeypot")
    parser.add_argument(
    '-p', '--port', type=int, required=True, help="Port to listen on")
    parser.add_argument(
    '-u', '--username', type=str, default=None, help="Optional username to enforce")
    parser.add_argument(
    '-pw', '--password', type=str, default=None, help="Optional password to enforce")
    parser.add_argument(
    '-s', '--ssh', action="store_true", help="Run SSH honeypot")
    parser.add_argument(
    '-w', '--http', action="store_true", help="Run HTTP/WordPress honeypot")

    args = parser.parse_args()

    try:
        if args.ssh:
            print(f"[-] Running SSH Honeypot on {args.address}:{args.port} ...")
            # Pass username/password if provided
            run_ssh_honeypot(
                address=args.address,
                port=args.port,
                username=args.username,
                password=args.password
            )

        elif args.http:
            # Provide default credentials if not specified
            username = args.username if args.username else "admin"
            password = args.password if args.password else "password"

            print(f"[-] Running HTTP Honeypot on port {args.port} ...")
            print(f"    Username: {username} | Password: {password}")
            run_web_honeypot(port=args.port, username=username, password=password)

        else:
            print("[!] Please choose a honeypot type: SSH (--ssh) or HTTP (--http)")

    except KeyboardInterrupt:
        print("\n[!] Honeypot stopped by user. Exiting...")
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
