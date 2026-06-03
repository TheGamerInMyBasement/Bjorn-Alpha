# actions/ble_tracker.py
# Tracks BLE devices over time using RSSI — logs appearance/disappearance and proximity estimates.
# Passive only, no connections made.

import subprocess
import csv
import json
import os
import re
import time
import logging
from datetime import datetime
from rich.console import Console
from rich.table import Table
from shared import SharedData
from logger import Logger
from ntfy import send_ntfy

logger = Logger(name="ble_tracker.py", level=logging.DEBUG)

b_class = "BLETracker"
b_module = "ble_tracker"
b_status = "BLETracker"
b_port = 0
b_parent = None
b_priority = 4

# Rough RSSI to distance mapping
def rssi_to_proximity(rssi):
    if rssi == "N/A" or rssi is None:
        return "Unknown"
    rssi = int(rssi)
    if rssi >= -50:
        return "Immediate (<1m)"
    elif rssi >= -70:
        return "Near (1-3m)"
    elif rssi >= -85:
        return "Far (3-10m)"
    else:
        return "Very Far (>10m)"


class BLETracker:
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.logger = logger
        self.console = Console()

        self.output_dir = f"{shared_data.currentdir}/data/output/"
        self.csv_file = f"{self.output_dir}ble_tracker.csv"
        self.json_file = f"{self.output_dir}ble_tracker.json"
        self.history_file = f"{self.output_dir}ble_tracker_history.csv"

        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

        # Init history CSV
        if not os.path.exists(self.history_file):
            with open(self.history_file, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Timestamp", "MAC", "Name", "RSSI", "Proximity", "Event"])

    def get_timestamp(self):
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def execute(self):
        try:
            self.logger.info("Starting BLE tracker scan...")

            # Load previously known devices
            previous = self._load_previous()
            current = self._scan_current()

            if not current and not previous:
                self.logger.info("No BLE devices detected.")
                return 'failed'

            # Diff: new, lost, and updated devices
            prev_macs = set(previous.keys())
            curr_macs = set(current.keys())

            new_devices = curr_macs - prev_macs
            lost_devices = prev_macs - curr_macs
            seen_devices = curr_macs & prev_macs

            events = []
            timestamp = self.get_timestamp()

            for mac in new_devices:
                d = current[mac]
                prox = rssi_to_proximity(d["rssi"])
                events.append([timestamp, mac, d["name"], d["rssi"], prox, "APPEARED"])
                self.logger.info(f"NEW device: {mac} ({d['name']}) RSSI={d['rssi']} {prox}")

            for mac in lost_devices:
                d = previous[mac]
                events.append([timestamp, mac, d["name"], d.get("rssi", "N/A"), "N/A", "DISAPPEARED"])
                self.logger.info(f"LOST device: {mac} ({d['name']})")

            for mac in seen_devices:
                d = current[mac]
                prox = rssi_to_proximity(d["rssi"])
                prev_rssi = previous[mac].get("rssi", "N/A")
                events.append([timestamp, mac, d["name"], d["rssi"], prox, "SEEN"])

                # Alert on significant RSSI change (device moving)
                try:
                    delta = abs(int(d["rssi"]) - int(prev_rssi))
                    if delta > 15:
                        self.logger.info(f"MOVING device: {mac} RSSI changed by {delta}dBm")
                        events[-1][5] = "MOVING"
                except (ValueError, TypeError):
                    pass

            # Save history
            self._append_history(events)

            # Save current snapshot
            self._write_csv(current)
            self._write_json(current)
            self._display_table(current, new_devices, lost_devices)

            # Notify on new or lost devices
            if new_devices:
                send_ntfy(f"BLE Tracker: {len(new_devices)} new device(s) appeared.")
            if lost_devices:
                send_ntfy(f"BLE Tracker: {len(lost_devices)} device(s) disappeared.")

            return 'success'

        except Exception as e:
            self.logger.error(f"BLETracker error: {e}")
            return 'failed'

    def _scan_current(self):
        """Scan for BLE devices and collect RSSI."""
        devices = {}
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
            time.sleep(10)
            proc.stdin.write("scan off\nquit\n")
            proc.stdin.flush()
            stdout, _ = proc.communicate(timeout=15)

            for line in stdout.splitlines():
                # Device name/MAC
                match = re.search(r'\[NEW\]\s+Device\s+([0-9A-Fa-f:]{17})\s+(.*)', line)
                if match:
                    mac = match.group(1).upper()
                    name = match.group(2).strip()
                    if mac not in devices:
                        devices[mac] = {"mac": mac, "name": name, "rssi": "N/A", "timestamp": self.get_timestamp()}
                    elif name and name != mac:
                        devices[mac]["name"] = name

                # RSSI values
                rssi_match = re.search(r'RSSI[:\s]+(-?\d+)', line)
                if rssi_match:
                    mac_match = re.search(r'([0-9A-Fa-f:]{17})', line)
                    if mac_match:
                        mac = mac_match.group(1).upper()
                        if mac in devices:
                            devices[mac]["rssi"] = int(rssi_match.group(1))

        except subprocess.TimeoutExpired:
            self.logger.warning("BLE tracker scan timed out")
            proc.kill()
        except Exception as e:
            self.logger.error(f"BLE scan error: {e}")

        return devices

    def _load_previous(self):
        """Load the last snapshot from CSV."""
        previous = {}
        if not os.path.exists(self.csv_file):
            return previous
        try:
            with open(self.csv_file, "r") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    mac = row.get("MAC", "").upper()
                    if mac:
                        previous[mac] = {
                            "mac": mac,
                            "name": row.get("Name", "Unknown"),
                            "rssi": row.get("RSSI", "N/A"),
                        }
        except Exception as e:
            self.logger.error(f"Error loading previous BLE snapshot: {e}")
        return previous

    def _append_history(self, events):
        """Append events to the history log."""
        try:
            with open(self.history_file, "a", newline="") as f:
                writer = csv.writer(f)
                writer.writerows(events)
        except Exception as e:
            self.logger.error(f"Error writing BLE history: {e}")

    def _write_csv(self, devices):
        try:
            with open(self.csv_file, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["MAC", "Name", "RSSI", "Proximity", "Timestamp"])
                for d in devices.values():
                    writer.writerow([
                        d["mac"], d["name"], d["rssi"],
                        rssi_to_proximity(d["rssi"]), d["timestamp"]
                    ])
        except Exception as e:
            self.logger.error(f"Error writing tracker CSV: {e}")

    def _write_json(self, devices):
        try:
            data = []
            for d in devices.values():
                entry = dict(d)
                entry["proximity"] = rssi_to_proximity(d["rssi"])
                data.append(entry)
            with open(self.json_file, "w") as f:
                json.dump(data, f, indent=4)
        except Exception as e:
            self.logger.error(f"Error writing tracker JSON: {e}")

    def _display_table(self, devices, new_macs, lost_macs):
        table = Table(title=f"BLE Tracker — {self.get_timestamp()}")
        table.add_column("MAC", style="cyan")
        table.add_column("Name", style="green")
        table.add_column("RSSI", style="yellow")
        table.add_column("Proximity", style="magenta")
        table.add_column("Status", style="bold")

        for mac, d in devices.items():
            status = "[green]NEW[/green]" if mac in new_macs else "SEEN"
            table.add_row(
                mac, d["name"], str(d["rssi"]),
                rssi_to_proximity(d["rssi"]), status
            )
        for mac in lost_macs:
            table.add_row(mac, "?", "N/A", "N/A", "[red]LOST[/red]")

        self.console.print(table)