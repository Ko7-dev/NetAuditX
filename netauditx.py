"""NetAuditX - Multi vendor SSH auditing tool."""

import csv
import os
import platform
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from getpass import getpass

# المصحح: استيراد محدد وتجنب Exception العامة في البداية
try:
    from netmiko import ConnectHandler, SSHDetect
except ImportError:
    # تم تغيير الأسماء لتناسب معايير Pylint للثوابت
    CONNECT_HANDLER = None
    SSH_DETECT = None
else:
    CONNECT_HANDLER = ConnectHandler
    SSH_DETECT = SSHDetect


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
    cmd = ["ping", "-n", "1", "-w", "1000", ip] if system == "windows" else \
          ["ping", "-c", "1", "-W", "1", ip]

    try:
        res = subprocess.run(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
        )
        return res.returncode == 0
    except subprocess.SubprocessError: # تم استبدال Exception بنوع محدد
        return False


def load_ips():
    """Load IP list."""
    devices = []
    if not os.path.exists(IN_FILE):
        return devices

    with open(IN_FILE, "r", encoding="utf-8") as f_in:
        for line in f_in:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",")
            ip_addr = parts[0].strip()
            dtype = parts[1].strip() if len(parts) > 1 else "auto"
            devices.append((ip_addr, dtype))
    return devices


def detect_device_type(ip_addr, user, pwd):
    """Auto detect device type."""
    if SSH_DETECT is None:
        return "linux"
    try:
        guesser = SSH_DETECT(
            device_type="autodetect",
            host=ip_addr,
            username=user,
            password=pwd,
            timeout=TIMEOUT,
        )
        return guesser.autodetect() or "linux"
    except Exception: # pylint: disable=broad-exception-caught
        return "linux"


def clean_output(text):
    """Remove ANSI chars."""
    if not text:
        return ""
    return re.sub(r"\x1b\[[0-9;]*m", "", str(text))


def run_ssh_command(conn, cmd):
    """Run SSH command safely."""
    try:
        return conn.send_command(cmd, read_timeout=15)
    except Exception: # pylint: disable=broad-exception-caught
        try:
            return conn.send_command_timing(cmd)
        except Exception: # pylint: disable=broad-exception-caught
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
        "uptime": clean_output(out).strip() or "N/A",
    }


def connect_and_audit(ip_addr, dtype, user, pwd):
    """Main worker."""
    res = {
        "ip": ip_addr, "status": "fail", "model": "N/A",
        "serial": "N/A", "uptime": "N/A", "error": "",
    }
    conn = None
    try:
        if not ping(ip_addr):
            res["status"] = "offline"
            return res

        if dtype == "auto":
            dtype = detect_device_type(ip_addr, user, pwd)

        if CONNECT_HANDLER is None:
            res["error"] = "missing netmiko"
            return res

        conn = CONNECT_HANDLER(
            device_type=dtype, host=ip_addr, username=user, password=pwd, timeout=TIMEOUT,
        )
        cmd = build_cmd(dtype)
        output = run_ssh_command(conn, cmd)
        res.update(parse_linux(output))
        res["status"] = "success"
    except Exception as err: # pylint: disable=broad-exception-caught
        res["error"] = str(err)
    finally:
        if conn:
            conn.disconnect()
    return res


def save_to_csv(data):
    """Save CSV output."""
    keys = ["ip", "status", "model", "serial", "uptime", "error"]
    with open(OUT_FILE, "w", newline="", encoding="utf-8") as f_out:
        writer = csv.DictWriter(f_out, fieldnames=keys)
        writer.writeheader()
        writer.writerows(data)


def main():
    """Entry point."""
    user, pwd = get_credentials()
    devices = load_ips()
    if not devices:
        return

    results = []
    num_workers = min(MAX_WORKERS, len(devices))
    with ThreadPoolExecutor(max_workers=num_workers) as ex:
        futures = [ex.submit(connect_and_audit, ip, dt, user, pwd) for ip, dt in devices]
        for fut in as_completed(futures):
            results.append(fut.result())

    save_to_csv(results)
    print("Done:", OUT_FILE)


if __name__ == "__main__":
    main()
