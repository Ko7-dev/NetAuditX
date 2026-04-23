import os
import re
import csv
import platform
import subprocess
from getpass import getpass
from concurrent.futures import ThreadPoolExecutor, as_completed

from netmiko import ConnectHandler, SSHDetect

MAX_WORKERS = 50
TIMEOUT = 5


def get_credentials():
    username = os.getenv("NOC_USER") or input("Username: ")
    password = os.getenv("NOC_PASS") or getpass("Password: ")
    return username, password


def ping(ip):
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", "1000", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
    return subprocess.run(cmd, stdout=subprocess.DEVNULL).returncode == 0


def load_ips(file_path="ips.txt"):
    devices = []
    if not os.path.exists(file_path):
        print(f"[ERROR] File not found: {file_path}")
        return devices

    with open(file_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split(",")
            ip = parts[0]
            dtype = parts[1] if len(parts) > 1 else "auto"
            devices.append((ip, dtype))
    return devices


def detect_type(ip, username, password):
    try:
        guesser = SSHDetect(
            device_type="autodetect",
            host=ip,
            username=username,
            password=password,
        )
        return guesser.autodetect() or "linux"
    except:
        return "linux"


def strip_ansi(text):
    ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)


def run_command(conn, command):
    try:
        return conn.send_command(
            command,
            expect_string=r"[#>$\]]",
            read_timeout=10
        )
    except:
        try:
            return conn.send_command_timing(command)
        except:
            return ""


def parse_linux(output):
    output = strip_ansi(output)
    return {
        "model": "linux-host",
        "serial": "N/A",
        "uptime": output.strip()
    }


def connect_and_collect(ip, dtype, username, password):
    result = {
        "ip": ip,
        "status": "failed",
        "model": "N/A",
        "serial": "N/A",
        "uptime": "N/A",
        "error": "N/A",
    }

    try:
        if not ping(ip):
            result["status"] = "offline"
            return result

        if dtype == "auto":
            dtype = detect_type(ip, username, password)

        device = {
            "device_type": dtype,
            "host": ip,
            "username": username,
            "password": password,
            "timeout": TIMEOUT,
        }

        conn = ConnectHandler(**device)

        if "cisco" in dtype:
            cmd = "show version"
        elif "juniper" in dtype:
            cmd = "show chassis hardware"
        else:
            cmd = "uptime"

        raw = run_command(conn, cmd)

        parsed = None

        if "cisco" in dtype or "juniper" in dtype:
            try:
                parsed = conn.send_command(cmd, use_textfsm=True)
            except:
                parsed = None

        if isinstance(parsed, list) and parsed:
            data = parsed[0]
            result["model"] = data.get("hardware", data.get("model", "N/A"))
            result["serial"] = data.get("serial", "N/A")
            result["uptime"] = data.get("uptime", "N/A")
            result["status"] = "success"
        else:
            linux_data = parse_linux(raw)
            result.update(linux_data)
            result["status"] = "success"

        conn.disconnect()

    except Exception as e:
        result["error"] = str(e)

    return result


def save_results(results):
    keys = ["ip", "status", "model", "serial", "uptime", "error"]
    with open("audit_results.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(results)


def main():
    username, password = get_credentials()
    devices = load_ips()

    if not devices:
        return

    results = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [
            executor.submit(connect_and_collect, ip, dtype, username, password)
            for ip, dtype in devices
        ]

        for future in as_completed(futures):
            results.append(future.result())

    save_results(results)


if __name__ == "__main__":
    main()
