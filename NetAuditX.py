"""NetAuditX - Multi-vendor network auditing tool."""

import csv
import os
import platform
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from getpass import getpass

from netmiko import ConnectHandler, SSHDetect

MAX_WORKERS = int(os.getenv("NETAUDITX_WORKERS", "20"))
TIMEOUT = int(os.getenv("NETAUDITX_TIMEOUT", "10"))
RESULTS_FILE = "audit_results.csv"
IP_FILE = "ips.txt"


def get_credentials():
    """Get credentials from env or user input."""
    username = os.getenv("NOC_USER") or input("Username: ").strip()
    password = os.getenv("NOC_PASS") or getpass("Password: ")
    return username, password


def ping(ip):
    """Check if host is reachable."""
    system = platform.system().lower()

    cmd = ["ping", "-n", "1", "-w", "1000", ip] if system == "windows" else \
          ["ping", "-c", "1", "-W", "1", ip]

    try:
        return subprocess.run(cmd, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL,
                              check=False).returncode == 0
    except OSError:
        return False


def load_ips():
    """Load device list."""
    devices = []

    if not os.path.exists(IP_FILE):
        return devices

    with open(IP_FILE, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split(",")
            ip = parts[0].strip()
            dtype = parts[1].strip() if len(parts) > 1 else "auto"
            devices.append((ip, dtype))

    return devices


def detect_type(ip, username, password):
    """Auto-detect device type."""
    try:
        guesser = SSHDetect(
            device_type="autodetect",
            host=ip,
            username=username,
            password=password,
            timeout=TIMEOUT,
        )
        return guesser.autodetect() or "linux"
    except Exception:
        return "linux"


def strip_ansi(text):
    """Clean terminal output."""
    if not text:
        return ""
    pattern = re.compile(r"\x1B[@-_][0-?]*[ -/]*[@-~]")
    return pattern.sub("", str(text))


def run_command(conn, command):
    """Run SSH command safely."""
    try:
        return conn.send_command(command, read_timeout=15)
    except Exception:
        try:
            return conn.send_command_timing(command)
        except Exception:
            return ""


def build_command(dtype):
    """Return command per device type."""
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


def extract_result(dtype, parsed, raw):
    """Parse structured output if available."""
    if isinstance(parsed, list) and parsed:
        data = parsed[0]
        return {
            "model": str(data.get("hardware") or data.get("model") or "N/A"),
            "serial": str(data.get("serial") or "N/A"),
            "uptime": str(data.get("uptime") or "N/A"),
        }

    if "linux" in dtype:
        return parse_linux(raw)

    return {
        "model": "N/A",
        "serial": "N/A",
        "uptime": strip_ansi(raw).strip() or "N/A",
    }


def connect_device(ip, dtype, username, password):
    """Handle full device connection lifecycle."""
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

        conn = ConnectHandler(
            device_type=dtype,
            host=ip,
            username=username,
            password=password,
            timeout=TIMEOUT,
        )

        command = build_command(dtype)
        raw = run_command(conn, command)

        parsed = None
        if "cisco" in dtype or "juniper" in dtype:
            try:
                parsed = conn.send_command(command, use_textfsm=True)
            except Exception:
                parsed = None

        result.update(extract_result(dtype, parsed, raw))
        result["status"] = "success"

        return result

    except Exception as exc:
        result["error"] = str(exc)
        return result

    finally:
        if conn:
            try:
                conn.disconnect()
            except Exception:
                pass


def save_results(results):
    """Save CSV output."""
    keys = ["ip", "status", "model", "serial", "uptime", "error"]

    with open(RESULTS_FILE, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=keys)
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
