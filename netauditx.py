"""NetAuditX - Network auditing tool."""

import csv
import os
import platform
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from getpass import getpass

# =========================
# SAFE IMPORT (Pylint FIX)
# =========================
try:
    from netmiko import ConnectHandler, SSHDetect  # type: ignore
except ImportError:
    ConnectHandler = None
    SSHDetect = None


MAX_WORKERS = int(os.getenv("NETAUDITX_WORKERS", "20"))
TIMEOUT = int(os.getenv("NETAUDITX_TIMEOUT", "10"))
RESULTS_FILE = "audit_results.csv"
IP_FILE = "ips.txt"


def get_credentials():
    """Get credentials."""
    username = os.getenv("NOC_USER") or input("Username: ").strip()
    password = os.getenv("NOC_PASS") or getpass("Password: ")
    return username, password


def ping(ip):
    """Check host reachability."""
    system = platform.system().lower()

    cmd = ["ping", "-n", "1", "-w", "1000", ip] if system == "windows" else ["ping", "-c", "1", "-W", "1", ip]

    try:
        return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    except OSError:
        return False


def load_ips():
    """Load inventory."""
    devices = []

    if not os.path.exists(IP_FILE):
        return devices

    with open(IP_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split(",")
            ip = parts[0].strip()
            dtype = parts[1].strip() if len(parts) > 1 else "auto"
            devices.append((ip, dtype))

    return devices


def detect_type(ip, username, password):
    """Detect device type."""
    try:
        if SSHDetect is None:
            return "linux"

        guesser = SSHDetect(
            device_type="autodetect",
            host=ip,
            username=username,
            password=password,
            timeout=TIMEOUT,
        )
        return guesser.autodetect() or "linux"
    except (OSError, ValueError):
        return "linux"


def strip_ansi(text):
    """Clean output."""
    if not text:
        return ""
    return re.sub(r"\x1B[@-_][0-?]*[ -/]*[@-~]", "", str(text))


def run_command(conn, command):
    """Run SSH command."""
    try:
        return conn.send_command(command, read_timeout=15)
    except (OSError, ValueError):
        try:
            return conn.send_command_timing(command)
        except (OSError, ValueError):
            return ""


def build_command(dtype):
    """Select command."""
    if "cisco" in dtype:
        return "show version"
    if "juniper" in dtype:
        return "show chassis hardware"
    return "uptime"


def parse_linux(output):
    """Parse Linux output."""
    return {
        "model": "linux-host",
        "serial": "N/A",
        "uptime": strip_ansi(output).strip() or "N/A",
    }


def connect_device(ip, dtype, username, password):
    """Main worker function."""
    result = {
        "ip": ip,
        "status": "failed",
        "model": "N/A",
        "serial": "N/A",
        "uptime": "N/A",
        "error": "",
    }

    conn = None

    try:
        if not ping(ip):
            result["status"] = "offline"
            return result

        if dtype == "auto":
            dtype = detect_type(ip, username, password)

        if ConnectHandler is None:
            result["error"] = "netmiko missing"
            return result

        conn = ConnectHandler(
            device_type=dtype,
            host=ip,
            username=username,
            password=password,
            timeout=TIMEOUT,
        )

        cmd = build_command(dtype)
        raw = run_command(conn, cmd)

        result.update(parse_linux(raw))
        result["status"] = "success"

        return result

    except (OSError, ValueError) as exc:
        result["error"] = str(exc)
        return result

    finally:
        if conn:
            try:
                conn.disconnect()
            except (OSError, ValueError):
                pass


def save_results(results):
    """Save CSV."""
    keys = ["ip", "status", "model", "serial", "uptime", "error"]

    with open(RESULTS_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(results)


def main():
    """Entry point."""
    username, password = get_credentials()
    devices = load_ips()

    if not devices:
        print("No devices found")
        return

    results = []
    workers = min(MAX_WORKERS, len(devices))

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(connect_device, ip, dtype, username, password)
            for ip, dtype in devices
        ]

        for future in as_completed(futures):
            results.append(future.result())

    save_results(results)
    print(f"Saved: {RESULTS_FILE}")


if __name__ == "__main__":
    main()
