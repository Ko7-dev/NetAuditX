"""NetAuditX - Multi vendor SSH auditing tool."""

import csv
import os
import platform
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from getpass import getpass

try:
    from netmiko import ConnectHandler, SSHDetect
except Exception:
    ConnectHandler = None
    SSHDetect = None


MAX_WORKERS = int(os.getenv("WORKERS", "20"))
TIMEOUT = int(os.getenv("TIMEOUT", "10"))
OUT_FILE = "audit_results.csv"
IN_FILE = "ips.txt"


def get_credentials():
    """Get login credentials."""
    user = os.getenv("USER") or input("User: ").strip()
    pwd = os.getenv("PASS") or getpass("Pass: ")
    return user, pwd


def ping(ip):
    """Check if host is alive."""
    system = platform.system().lower()

    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", "1000", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]

    try:
        res = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        return res.returncode == 0
    except Exception:
        return False


def load_ips():
    """Load IP list."""
    devices = []

    if not os.path.exists(IN_FILE):
        return devices

    with open(IN_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split(",")
            ip = parts[0].strip()
            dtype = parts[1].strip() if len(parts) > 1 else "auto"
            devices.append((ip, dtype))

    return devices


def detect(ip, user, pwd):
    """Auto detect device type."""
    try:
        if SSHDetect is None:
            return "linux"

        d = SSHDetect(
            device_type="autodetect",
            host=ip,
            username=user,
            password=pwd,
            timeout=TIMEOUT,
        )
        return d.autodetect() or "linux"
    except Exception:
        return "linux"


def clean(text):
    """Remove ANSI chars."""
    if not text:
        return ""
    return re.sub(r"\x1b\[[0-9;]*m", "", str(text))


def run(conn, cmd):
    """Run SSH command safely."""
    try:
        return conn.send_command(cmd, read_timeout=15)
    except Exception:
        try:
            return conn.send_command_timing(cmd)
        except Exception:
            return ""


def build_cmd(dtype):
    """Select command per device."""
    if "cisco" in dtype:
        return "show version"
    if "juniper" in dtype:
        return "show chassis hardware"
    return "uptime"


def parse_linux(out):
    """Parse Linux output."""
    return {
        "model": "linux",
        "serial": "N/A",
        "uptime": clean(out).strip() or "N/A",
    }


def connect(ip, dtype, user, pwd):
    """Main worker."""
    res = {
        "ip": ip,
        "status": "fail",
        "model": "N/A",
        "serial": "N/A",
        "uptime": "N/A",
        "error": "",
    }

    conn = None

    try:
        if not ping(ip):
            res["status"] = "offline"
            return res

        if dtype == "auto":
            dtype = detect(ip, user, pwd)

        if ConnectHandler is None:
            res["error"] = "missing netmiko"
            return res

        conn = ConnectHandler(
            device_type=dtype,
            host=ip,
            username=user,
            password=pwd,
            timeout=TIMEOUT,
        )

        cmd = build_cmd(dtype)
        output = run(conn, cmd)

        res.update(parse_linux(output))
        res["status"] = "success"

        return res

    except Exception as e:
        res["error"] = str(e)
        return res

    finally:
        try:
            if conn:
                conn.disconnect()
        except Exception:
            pass


def save(data):
    """Save CSV output."""
    keys = ["ip", "status", "model", "serial", "uptime", "error"]

    with open(OUT_FILE, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        w.writerows(data)


def main():
    """Entry point."""
    user, pwd = get_credentials()
    devices = load_ips()

    if not devices:
        print("No devices found")
        return

    results = []
    workers = min(MAX_WORKERS, len(devices))

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [
            ex.submit(connect, ip, dtype, user, pwd)
            for ip, dtype in devices
        ]

        for f in as_completed(futures):
            results.append(f.result())

    save(results)
    print("Done:", OUT_FILE)


if __name__ == "__main__":
    main()
