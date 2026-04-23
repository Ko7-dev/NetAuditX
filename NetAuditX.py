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
    username = os.getenv("NOC_USER") or input("Username: ").strip()
    password = os.getenv("NOC_PASS") or getpass("Password: ")
    return username, password


def ping(ip):
    system = platform.system().lower()

    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", "1000", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]

    try:
        return subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode == 0
    except FileNotFoundError:
        return True
    except Exception:
        return False


def load_ips(file_path=IP_FILE):
    devices = []

    if not os.path.exists(file_path):
        print(f"[ERROR] File not found: {file_path}")
        return devices

    with open(file_path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 1 or not parts[0]:
                print(f"[WARN] Skipping invalid line {line_no}: {line}")
                continue

            ip = parts[0]
            dtype = parts[1].lower() if len(parts) > 1 and parts[1] else "auto"
            devices.append((ip, dtype))

    return devices


def detect_type(ip, username, password):
    try:
        guesser = SSHDetect(
            device_type="autodetect",
            host=ip,
            username=username,
            password=password,
            timeout=TIMEOUT,
        )
        detected = guesser.autodetect()
        return detected or "linux"
    except Exception:
        return "linux"


def strip_ansi(text):
    if not text:
        return ""
    ansi_escape = re.compile(r"\x1B[@-_][0-?]*[ -/]*[@-~]")
    return ansi_escape.sub("", str(text))


def run_command(conn, command):
    try:
        return conn.send_command(
            command,
            expect_string=r"[#>$\]]",
            read_timeout=15,
        )
    except Exception:
        try:
            return conn.send_command_timing(command)
        except Exception:
            return ""


def parse_linux(output):
    cleaned = strip_ansi(output).strip()
    return {
        "model": "linux-host",
        "serial": "N/A",
        "uptime": cleaned if cleaned else "N/A",
    }


def get_first_value(data, keys, default="N/A"):
    if not isinstance(data, dict):
        return default

    lowered = {str(k).lower(): v for k, v in data.items()}
    for key in keys:
        value = lowered.get(key.lower())
        if value not in (None, "", []):
            if isinstance(value, list):
                return ", ".join(str(x) for x in value)
            return str(value)
    return default


def parse_textfsm_result(dtype, parsed, raw_output=""):
    if not isinstance(parsed, list) or not parsed:
        return None

    data = parsed[0]

    if "cisco" in dtype:
        model = get_first_value(data, ["HARDWARE", "MODEL", "PRODUCT_ID"])
        serial = get_first_value(data, ["SERIAL", "SERIAL_NUMBER"])
        uptime = get_first_value(data, ["UPTIME"])
        return {
            "model": model,
            "serial": serial,
            "uptime": uptime,
        }

    if "juniper" in dtype:
        model = get_first_value(data, ["MODEL", "MODEL_NUMBER", "DESCRIPTION", "ITEM"])
        serial = get_first_value(data, ["SERIAL", "SERIAL_NUMBER"])
        uptime = get_first_value(data, ["UPTIME"])
        return {
            "model": model,
            "serial": serial,
            "uptime": uptime,
        }

    return None


def build_command(dtype):
    if "cisco" in dtype:
        return "show version"
    if "juniper" in dtype:
        return "show chassis hardware"
    return "uptime"


def connect_and_collect(ip, dtype, username, password):
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

        device = {
            "device_type": dtype,
            "host": ip,
            "username": username,
            "password": password,
            "timeout": TIMEOUT,
            "conn_timeout": TIMEOUT,
            "banner_timeout": TIMEOUT,
        }

        conn = ConnectHandler(**device)

        command = build_command(dtype)
        raw = run_command(conn, command)
        raw_clean = strip_ansi(raw)

        parsed = None
        if "cisco" in dtype or "juniper" in dtype:
            try:
                parsed = conn.send_command(command, use_textfsm=True)
            except Exception:
                parsed = None

        parsed_data = parse_textfsm_result(dtype, parsed, raw_clean)

        if parsed_data:
            result.update(parsed_data)
        else:
            if "linux" in dtype or dtype == "linux":
                result.update(parse_linux(raw_clean))
            else:
                result["uptime"] = raw_clean.strip() if raw_clean.strip() else "N/A"

        result["status"] = "success"
        return result

    except Exception as e:
        result["error"] = str(e)
        return result

    finally:
        try:
            if conn is not None:
                conn.disconnect()
        except Exception:
            pass


def save_results(results, file_path=RESULTS_FILE):
    keys = ["ip", "status", "model", "serial", "uptime", "error"]

    with open(file_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(results)


def main():
    username, password = get_credentials()
    devices = load_ips()

    if not devices:
        print("[ERROR] No devices found in ips.txt")
        return

    results = [None] * len(devices)

    workers = min(MAX_WORKERS, len(devices))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {
            executor.submit(connect_and_collect, ip, dtype, username, password): idx
            for idx, (ip, dtype) in enumerate(devices)
        }

        for future in as_completed(future_map):
            idx = future_map[future]
            try:
                results[idx] = future.result()
            except Exception as e:
                ip, _ = devices[idx]
                results[idx] = {
                    "ip": ip,
                    "status": "failed",
                    "model": "N/A",
                    "serial": "N/A",
                    "uptime": "N/A",
                    "error": str(e),
                }

    save_results(results)
    print(f"[OK] Results saved to {RESULTS_FILE}")


if __name__ == "__main__":
    main()
