NetAuditX

A Python-based utility designed for multi-vendor network device auditing and inventory collection. The tool automates the process of connecting to multiple nodes, executing system commands, and exporting results into a structured format.
Key Functionalities

    Concurrency: Utilizes ThreadPoolExecutor to handle up to 50 simultaneous connections, significantly reducing execution time for large inventories.

    Multi-Vendor Support: Compatible with Cisco IOS, Juniper Junos, and standard Linux hosts.

    Intelligent Device Detection: Features an auto-detect mechanism via SSHDetect to identify the operating system when not explicitly defined in the inventory.

    Data Normalization: Includes ANSI escape sequence stripping to ensure clean, human-readable output from various terminal types.

    Robust Connectivity: Implements pre-connection ICMP checks (Ping) and multi-layered command execution (Expect-string & Timing) to handle unstable SSH sessions.

Technical Structure

The tool is built with a modular approach:

    Credential Management: Supports environmental variables or secure runtime input.

    Inventory Loading: Parses a simple CSV-style ips.txt file.

    Data Extraction: Uses TextFSM for structured parsing on network appliances and regex-based cleaning for Linux hosts.

    Reporting: Generates a audit_results.csv file containing IP, Status, Model, Serial Number, and Uptime.

Prerequisites

    Python 3.x

    Netmiko (Connection handling)

    NTC-Templates (Required for TextFSM parsing)

How to Use

    Prepare Inventory: Create a file named ips.txt in the root directory.

        Format: IP,device_type (e.g., 10.0.0.1,cisco_ios or 10.0.0.2,auto).

    Environment Setup:
    Bash

    pip install netmiko ntc-templates

    Execution:
    Bash

    python NetAuditX.py

Limitations & Scope

    This tool is intended for read-only auditing tasks.

    The accuracy of auto detection depends on the device's SSH banner and response latency.

    Linux host auditing requires standard uptime command availability.
