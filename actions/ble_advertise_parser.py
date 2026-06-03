# actions/ble_advertise_parser.py
# Parses BLE advertisement payloads — iBeacon, Eddystone, manufacturer data, device type fingerprinting.
# Passive read-only recon, no connections made.

import subprocess
import csv
import json
import os
import re
import struct
import logging
from datetime import datetime
from rich.console import Console
from rich.table import Table
from shared import SharedData
from logger import Logger
from ntfy import send_ntfy

logger = Logger(name="ble_advertise_parser.py", level=logging.DEBUG)

b_class = "BLEAdvertiseParser"
b_module = "ble_advertise_parser"
b_status = "BLEAdvertiseParser"
b_port = 0
b_parent = None
b_priority = 3

# Known manufacturer IDs (Bluetooth SIG assigned numbers)
MANUFACTURER_IDS = {
    0x004C: "Apple",
    0x0006: "Microsoft",
    0x0075: "Samsung",
    0x00E0: "Google",
    0x0059: "Nordic Semiconductor",
    0x0499: "Ruuvi Innovations",
    0x0157: "Garmin",
    0x0171: "Amazon",
    0x0087: "Polar",
    0x0001: "Ericsson",
    0x000F: "Broadcom",
    0x0046: "Motorola",
    0x00D7: "Bose",
    0x008C: "Plantronics",
}

# Device type fingerprinting based on service UUIDs in advertisements
SERVICE_FINGERPRINTS = {
    "0000180d": "Heart Rate Monitor",
    "0000180f": "Battery Device",
    "00001812": "HID Device (keyboard/mouse)",
    "0000181a": "Environmental Sensor",
    "0000fe95": "Xiaomi Device",
    "0000fd6f": "COVID Exposure Notification",
    "0000feaa": "Eddystone Beacon",
    "0000fd5a": "SUUNTO Device",
    "0000fda5": "Tile Tracker",
    "0000fe9a": "Estimote Beacon",
}


class BLEAdvertiseParser:
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.logger = logger
        self.console = Console()

        self.output_dir = f"{shared_data.currentdir}/data/output/"
        self.csv_file = f"{self.output_dir}ble_advertise.csv"
        self.json_file = f"{self.output_dir}ble_advertise.json"

        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def get_timestamp(self):
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def execute(self):
        try:
            self.logger.info("Starting BLE advertisement parser...")
            raw_adv = self._capture_advertisements()
            parsed = self._parse_all(raw_adv)

            if parsed:
                self._write_csv(parsed)
                self._write_json(parsed)
                self._display_table(parsed)
                send_ntfy(f"BLE Adv Parser: found {len(parsed)} devices with parseable advertisements.")
                return 'success'
            else:
                self.logger.info("No parseable advertisements found.")
                return 'failed'
        except Exception as e:
            self.logger.error(f"BLEAdvertiseParser error: {e}")
            return 'failed'

    def _capture_advertisements(self):
        """Capture raw BLE advertisement data using hcidump or btmon."""
        raw_lines = []

        # Use btmon which gives structured output
        try:
            proc = subprocess.Popen(
                ["btmon"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            # Also start a scan to trigger advertisements
            scan_proc = subprocess.Popen(
                ["hcitool", "lescan", "--passive", "--duplicates"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            import threading, time

            def read_output():
                try:
                    for line in proc.stdout:
                        raw_lines.append(line.rstrip())
                        if len(raw_lines) > 500:
                            break
                except Exception:
                    pass

            t = threading.Thread(target=read_output)
            t.start()
            time.sleep(10)
            proc.terminate()
            scan_proc.terminate()
            t.join(timeout=2)

        except Exception as e:
            self.logger.warning(f"btmon capture failed: {e}, falling back to bluetoothctl")
            raw_lines = self._capture_via_bluetoothctl()

        return raw_lines

    def _capture_via_bluetoothctl(self):
        """Fallback: capture via bluetoothctl and parse what we can."""
        try:
            proc = subprocess.Popen(
                ["bluetoothctl"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            proc.stdin.write("scan on\n")
            proc.stdin.flush()
            import time
            time.sleep(10)
            proc.stdin.write("scan off\nquit\n")
            proc.stdin.flush()
            stdout, _ = proc.communicate(timeout=15)
            return stdout.splitlines()
        except Exception as e:
            self.logger.error(f"bluetoothctl fallback failed: {e}")
            return []

    def _parse_all(self, lines):
        """Parse captured lines into structured device records."""
        devices = {}

        for line in lines:
            # Look for device entries from bluetoothctl
            new_match = re.search(r'\[NEW\]\s+Device\s+([0-9A-Fa-f:]{17})\s+(.*)', line)
            if new_match:
                mac = new_match.group(1).upper()
                name = new_match.group(2).strip()
                if mac not in devices:
                    devices[mac] = self._empty_record(mac)
                if name and name != mac:
                    devices[mac]["name"] = name
                continue

            # RSSI
            rssi_match = re.search(r'([0-9A-Fa-f:]{17}).*RSSI[:\s]+(-?\d+)', line)
            if rssi_match:
                mac = rssi_match.group(1).upper()
                if mac not in devices:
                    devices[mac] = self._empty_record(mac)
                devices[mac]["rssi"] = int(rssi_match.group(2))
                continue

            # UUID service advertisements
            uuid_match = re.search(r'([0-9A-Fa-f:]{17}).*UUID[:\s]+([0-9a-fA-F-]{8,36})', line)
            if uuid_match:
                mac = uuid_match.group(1).upper()
                uuid = uuid_match.group(2).lower()
                if mac not in devices:
                    devices[mac] = self._empty_record(mac)
                devices[mac]["service_uuids"].add(uuid)
                # Fingerprint device type
                short = uuid.replace("-", "")[:8]
                if short in SERVICE_FINGERPRINTS:
                    devices[mac]["device_type"] = SERVICE_FINGERPRINTS[short]
                continue

            # iBeacon detection from btmon output
            if "02 01" in line and "FF 4C 00 02 15" in line.upper():
                mac_match = re.search(r'([0-9A-Fa-f:]{17})', line)
                if mac_match:
                    mac = mac_match.group(1).upper()
                    if mac not in devices:
                        devices[mac] = self._empty_record(mac)
                    devices[mac]["adv_type"] = "iBeacon"
                    devices[mac]["device_type"] = "Apple iBeacon"

            # Eddystone detection
            if "feaa" in line.lower() or "FEAA" in line:
                mac_match = re.search(r'([0-9A-Fa-f:]{17})', line)
                if mac_match:
                    mac = mac_match.group(1).upper()
                    if mac not in devices:
                        devices[mac] = self._empty_record(mac)
                    devices[mac]["adv_type"] = "Eddystone"
                    devices[mac]["device_type"] = "Eddystone Beacon"

        # Finalize records
        result = []
        for mac, record in devices.items():
            record["service_uuids"] = list(record["service_uuids"])
            record["timestamp"] = self.get_timestamp()
            result.append(record)

        return result

    def _empty_record(self, mac):
        return {
            "mac": mac,
            "name": "Unknown",
            "rssi": "N/A",
            "adv_type": "Generic",
            "device_type": "Unknown",
            "manufacturer": "Unknown",
            "service_uuids": set(),
            "timestamp": ""
        }

    def _write_csv(self, results):
        try:
            with open(self.csv_file, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["MAC", "Name", "RSSI", "Adv Type", "Device Type", "Manufacturer", "Service UUIDs", "Timestamp"])
                for d in results:
                    writer.writerow([
                        d["mac"], d["name"], d["rssi"],
                        d["adv_type"], d["device_type"], d["manufacturer"],
                        "; ".join(d["service_uuids"]), d["timestamp"]
                    ])
        except Exception as e:
            self.logger.error(f"Error writing advertise CSV: {e}")

    def _write_json(self, results):
        try:
            with open(self.json_file, "w") as f:
                json.dump(results, f, indent=4)
        except Exception as e:
            self.logger.error(f"Error writing advertise JSON: {e}")

    def _display_table(self, results):
        table = Table(title="BLE Advertisement Parser Results")
        table.add_column("MAC", style="cyan")
        table.add_column("Name", style="green")
        table.add_column("RSSI", style="yellow")
        table.add_column("Type", style="magenta")
        table.add_column("Device", style="blue")
        table.add_column("Manufacturer", style="red")

        for d in results:
            table.add_row(
                d["mac"], d["name"], str(d["rssi"]),
                d["adv_type"], d["device_type"], d["manufacturer"]
            )
        self.console.print(table)