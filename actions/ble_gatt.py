# actions/ble_gatt.py
# Enumerates GATT services and characteristics from nearby BLE devices.
# Read-only passive recon — no writes, no pairing attempts.

import subprocess
import csv
import json
import os
import re
import logging
from datetime import datetime
from rich.console import Console
from rich.table import Table
from shared import SharedData
from logger import Logger
from ntfy import send_ntfy

logger = Logger(name="ble_gatt.py", level=logging.DEBUG)

b_class = "BLEGattScanner"
b_module = "ble_gatt"
b_status = "BLEGattScanner"
b_port = 0
b_parent = None
b_priority = 2

class BLEGattScanner:
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.logger = logger
        self.console = Console()

        self.output_dir = f"{shared_data.currentdir}/data/output/"
        self.csv_file = f"{self.output_dir}ble_gatt.csv"
        self.json_file = f"{self.output_dir}ble_gatt.json"

        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def get_timestamp(self):
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def execute(self):
        try:
            devices = self._load_known_devices()
            if not devices:
                self.logger.info("No BLE devices found from previous scan. Run BLEScanner first.")
                return 'failed'

            results = []
            for mac in devices:
                self.logger.info(f"Enumerating GATT services for {mac}...")
                services = self._enumerate_gatt(mac)
                if services:
                    results.append({"mac": mac, "services": services, "timestamp": self.get_timestamp()})
                    self.logger.info(f"Found {len(services)} services on {mac}")

            if results:
                self._write_csv(results)
                self._write_json(results)
                self._display_table(results)
                send_ntfy(f"BLE GATT scan complete. Enumerated {len(results)} devices.")
                return 'success'
            else:
                self.logger.info("No GATT services found.")
                return 'failed'
        except Exception as e:
            self.logger.error(f"BLEGattScanner error: {e}")
            return 'failed'

    def _load_known_devices(self):
        """Load MAC addresses from previous ble_scan.csv"""
        scan_csv = f"{self.output_dir}ble_scan.csv"
        if not os.path.exists(scan_csv):
            return []
        macs = []
        try:
            with open(scan_csv, "r") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row.get("MAC"):
                        macs.append(row["MAC"])
        except Exception as e:
            self.logger.error(f"Error reading ble_scan.csv: {e}")
        return macs

    def _enumerate_gatt(self, mac):
        """Use gatttool or bluetoothctl to enumerate GATT services."""
        services = []

        # Try bluetoothctl gatt browse
        try:
            proc = subprocess.Popen(
                ["bluetoothctl"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            commands = f"connect {mac}\nlist-attributes {mac}\ndisconnect {mac}\nquit\n"
            stdout, _ = proc.communicate(input=commands, timeout=20)

            current_service = None
            for line in stdout.splitlines():
                # Parse service UUIDs
                svc_match = re.search(r'Service\s+([0-9a-fA-F-]{36})', line)
                if svc_match:
                    current_service = {
                        "uuid": svc_match.group(1),
                        "name": self._lookup_uuid(svc_match.group(1)),
                        "characteristics": []
                    }
                    services.append(current_service)

                # Parse characteristic UUIDs
                char_match = re.search(r'Characteristic\s+([0-9a-fA-F-]{36})', line)
                if char_match and current_service:
                    current_service["characteristics"].append({
                        "uuid": char_match.group(1),
                        "name": self._lookup_uuid(char_match.group(1))
                    })

        except subprocess.TimeoutExpired:
            self.logger.warning(f"GATT enumeration timed out for {mac}")
            proc.kill()
        except Exception as e:
            self.logger.error(f"GATT enumeration failed for {mac}: {e}")

        return services

    def _lookup_uuid(self, uuid):
        """Look up common BLE service/characteristic UUIDs."""
        # Common 16-bit UUIDs embedded in 128-bit form
        known = {
            "00001800": "Generic Access",
            "00001801": "Generic Attribute",
            "0000180a": "Device Information",
            "0000180d": "Heart Rate",
            "0000180f": "Battery Service",
            "00001810": "Blood Pressure",
            "00001812": "HID",
            "0000181a": "Environmental Sensing",
            "0000181c": "User Data",
            "00002a00": "Device Name",
            "00002a01": "Appearance",
            "00002a04": "Peripheral Preferred Connection Parameters",
            "00002a19": "Battery Level",
            "00002a24": "Model Number String",
            "00002a25": "Serial Number String",
            "00002a26": "Firmware Revision String",
            "00002a27": "Hardware Revision String",
            "00002a28": "Software Revision String",
            "00002a29": "Manufacturer Name String",
            "00002a37": "Heart Rate Measurement",
            "00002a6e": "Temperature",
            "00002a6f": "Humidity",
        }
        # Extract short UUID from full UUID string
        short = uuid.replace("-", "")[:8].lower()
        return known.get(short, "Unknown")

    def _write_csv(self, results):
        try:
            with open(self.csv_file, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["MAC", "Service UUID", "Service Name", "Characteristic UUID", "Characteristic Name", "Timestamp"])
                for device in results:
                    for svc in device["services"]:
                        if svc["characteristics"]:
                            for char in svc["characteristics"]:
                                writer.writerow([
                                    device["mac"],
                                    svc["uuid"],
                                    svc["name"],
                                    char["uuid"],
                                    char["name"],
                                    device["timestamp"]
                                ])
                        else:
                            writer.writerow([device["mac"], svc["uuid"], svc["name"], "", "", device["timestamp"]])
        except Exception as e:
            self.logger.error(f"Error writing GATT CSV: {e}")

    def _write_json(self, results):
        try:
            with open(self.json_file, "w") as f:
                json.dump(results, f, indent=4)
        except Exception as e:
            self.logger.error(f"Error writing GATT JSON: {e}")

    def _display_table(self, results):
        for device in results:
            table = Table(title=f"GATT Services: {device['mac']}")
            table.add_column("Service", style="cyan")
            table.add_column("Service Name", style="green")
            table.add_column("Characteristics", style="yellow")
            for svc in device["services"]:
                chars = ", ".join([c["name"] for c in svc["characteristics"]]) or "None"
                table.add_row(svc["uuid"][:8], svc["name"], chars)
            self.console.print(table)