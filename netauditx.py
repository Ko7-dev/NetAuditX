"""NetAuditX - Professional multi-vendor SSH network auditing tool."""

# pylint: disable=broad-exception-caught,line-too-long,subprocess-run-check

import csv
import os
import platform
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from getpass import getpass

try:
    from netmiko import ConnectHandler, SSHDetect
except ImportError:
    ConnectHandler = None
    SSHDetect = None

# Global Configuration
WORKERS = int(os.getenv("NAX_WORKERS", "20"))
TIMEOUT = int(os.getenv("NAX_TIMEOUT", "10"))
OUT_FILE = "audit_results.csv"
IN_FILE = "ips.txt"

# Robust Regex for IPv4 Validation
_IP_PATTERN = (
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_IP_RE = re.compile(_IP_PATTERN)

_VENDOR_CMDS = {
    "cisco": "show version",
    "juniper": "show chassis hardware",
}


def get_credentials():
    """Get SSH credentials from environment or user input."""
    user = os.getenv("NAX_USER") or input("User: ").strip()
    pwd = os.getenv("NAX_PASS") or getpass("Pass: ")
    return user, pwd


def ping(ip_addr):
    """Check host availability via ping."""
    system = platform.system().lower()
    cmd = (
        ["ping", "-n", "1", "-w", "1000", ip_addr]
        if system == "windows"
        else ["ping", "-c", "1", "-W", "1", ip_addr]
    )

    try:
        res = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False
        )
        return res.returncode == 0
    except Exception:
        return False


def load_inventory():
    """Load IP inventory from the ips.txt file."""
    devices = []
    if not os.path.exists(IN_FILE):
        return devices

    with open(IN_FILE, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split(",")
            ip_val = parts[0].strip()

            if not _IP_RE.match(ip_val):
                continue

            dtype = parts[1].strip() if len(parts) > 1 else "auto"
            devices.append((ip_val, dtype))

    return devices


def detect_device(ip_addr, user, pwd):
    """Auto-detect device type via Netmiko SSHDetect."""
    if SSHDetect is None:
        return None

    try:
        guesser = SSHDetect(
            device_type="autodetect",
            host=ip_addr,
            username=user,
            password=pwd,
            timeout=TIMEOUT,
        )
        return guesser.autodetect()
    except Exception:
        return None


def clean_ansi(text):
    """Remove ANSI escape sequences from terminal output."""
    if not text:
        return ""
    return re.sub(r"\x1B[@-_][0-?]*[ -/]*[@-~]", "", str(text))


def run_ssh(conn, cmd):
    """Run SSH command with a fallback mechanism for timing."""
    try:
        return conn.send_command(cmd, read_timeout=15)
    except Exception:
        try:
            return conn.send_command_timing(cmd)
        except Exception:
            return ""


def _vendor_cmd(device_type):
    """Map device type to specific audit command."""
    for key, cmd in _VENDOR_CMDS.items():
        if key in device_type:
            return cmd
    return "uptime"


def create_result(ip_addr):
    """Return a standard result dictionary structure."""
    return {
        "ip": ip_addr,
        "status": "failed",
        "vendor": "N/A",
        "uptime": "N/A",
        "error": "",
    }


def connect_and_audit(ip_addr, dtype, user, pwd):
    """Handle connection, data collection, and teardown for a device."""
    result = create_result(ip_addr)
    conn = None

    try:
        if not ping(ip_addr):
            result["status"] = "offline"
            return result

        if ConnectHandler is None:
            result["error"] = "netmiko missing"
            return result

        device_type = detect_device(ip_addr, user, pwd) if dtype == "auto" else dtype
        if not device_type:
            result["error"] = "detection failed"
            return result

        conn = ConnectHandler(
            device_type=device_type,
            host=ip_addr,
            username=user,
            password=pwd,
            timeout=TIMEOUT,
        )

        output = run_ssh(conn, _vendor_cmd(device_type))

        result["vendor"] = device_type.split("_")[0]
        result["uptime"] = clean_ansi(output).strip() or "N/A"
        result["status"] = "success"

    except Exception as err:
        result["error"] = str(err)

    finally:
        if conn:
            try:
                conn.disconnect()
            except Exception:
                pass

    return result


def save_results(results):
    """Write audit data to a CSV file."""
    fields = ["ip", "status", "vendor", "uptime", "error"]

    with open(OUT_FILE, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(results)


def main():
    """Main execution flow for NetAuditX."""
    user, pwd = get_credentials()
    devices = load_inventory()

    if not devices:
        print(f"No valid IPs found in {IN_FILE}")
        return

    results = []
    limit = min(WORKERS, len(devices))
    with ThreadPoolExecutor(max_workers=limit) as ex:
        futures = [
            ex.submit(connect_and_audit, ip, dtype, user, pwd)
            for ip, dtype in devices
        ]

        for f in as_completed(futures):
            results.append(f.result())

    save_results(results)
    print(f"Audit completed. Results saved to {OUT_FILE}")


if __name__ == "__main__":
    main()
