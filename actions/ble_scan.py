# actions/ble_scan.py
# Safe BLE advertisement scanner for Bjorn
# Mirrors the structure of scanning.py (NetworkScanner)

import subprocess
import csv
import json
import time
import threading
import os
import logging
from datetime import datetime
from rich.console import Console
from rich.table import Table
from shared import SharedData
from logger import Logger
from ntfy import send_ntfy

logger = Logger(name="ble_scan.py", level=logging.DEBUG)

b_class = "BLEScanner"
b_module = "ble_scan"
b_status = "BLEScanner"
b_port = 0
b_parent = None

class BLEScanner:
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.logger = logger
        self.console = Console()
        self.lock = threading.Lock()
        self.running = False

        self.output_dir = f"{shared_data.currentdir}/data/output/"
        self.csv_file = f"{self.output_dir}ble_scan.csv"
        self.json_file = f"{self.output_dir}ble_scan.json"

        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def get_timestamp(self):
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def run(self):
        self.running = True
        self.logger.info("Starting BLE scan...")
        send_ntfy("Starting BLEScan...")

        devices = self.scan_ble()
        self.write_csv(devices)
        self.write_json(devices)
        self.display_table(devices)

        send_ntfy(f"BLEScan complete. Found {len(devices)} devices.")
        self.logger.info(f"BLEScan complete. Found {len(devices)} devices.")
        self.running = False

        return devices

    def scan_ble(self):
        """
        Runs bluetoothctl scan and parses output.
        Safe: only listens for BLE advertisements.
        """
        cmd = ["bluetoothctl", "--timeout", "10", "scan", "on"]
        result = subprocess.run(cmd, capture_output=True, text=True)

        devices = []
        seen = set()

        for line in result.stdout.splitlines():
            if "Device" in line:
                parts = line.split()
                mac = parts[1]
                name = " ".join(parts[2:]) if len(parts) > 2 else "Unknown"

                if mac not in seen:
                    seen.add(mac)
                    devices.append({
                        "mac": mac,
                        "name": name,
                        "rssi": "N/A",  # bluetoothctl doesn't show RSSI
                        "timestamp": self.get_timestamp()
                    })

        return devices

    def write_csv(self, devices):
        with self.lock:
            try:
                with open(self.csv_file, "w", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow(["MAC", "Name", "RSSI", "Timestamp"])
                    for d in devices:
                        writer.writerow([d["mac"], d["name"], d["rssi"], d["timestamp"]])
            except Exception as e:
                self.logger.error(f"Error writing BLE CSV: {e}")

    def write_json(self, devices):
        with self.lock:
            try:
                with open(self.json_file, "w") as f:
                    json.dump(devices, f, indent=4)
            except Exception as e:
                self.logger.error(f"Error writing BLE JSON: {e}")

    def display_table(self, devices):
        table = Table(title="BLE Devices Found")

        table.add_column("MAC", style="cyan")
        table.add_column("Name", style="green")
        table.add_column("RSSI", style="yellow")
        table.add_column("Timestamp", style="magenta")

        for d in devices:
            table.add_row(d["mac"], d["name"], str(d["rssi"]), d["timestamp"])

        self.console.print(table)

    def execute(self, ip=None, port=None):
        return self.run()

