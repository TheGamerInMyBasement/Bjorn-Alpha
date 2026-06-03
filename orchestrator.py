# orchestrator.py
# Description:
# This file, orchestrator.py, is the heuristic Bjorn brain, and it is responsible for coordinating and executing various network scanning and offensive security actions 
# It manages the loading and execution of actions, handles retries for failed and successful actions, 
# and updates the status of the orchestrator.
#
# Key functionalities include:
# - Initializing and loading actions from a configuration file, including network and vulnerability scanners.
# - Managing the execution of actions on network targets, checking for open ports and handling retries based on success or failure.
# - Coordinating the execution of parent and child actions, ensuring actions are executed in a logical order.
# - Running the orchestrator cycle to continuously check for and execute actions on available network targets.
# - Handling and updating the status of the orchestrator, including scanning for new targets and performing vulnerability scans.
# - Implementing threading to manage concurrent execution of actions with a semaphore to limit active threads.
# - Logging events and errors to ensure maintainability and ease of debugging.
# - Handling graceful degradation by managing retries and idle states when no new targets are found.

import json
import importlib
import time
import logging
import sys
import threading
from datetime import datetime, timedelta
from actions.nmap_vuln_scanner import NmapVulnScanner
from init_shared import shared_data
from logger import Logger

logger = Logger(name="orchestrator.py", level=logging.DEBUG)


class Orchestrator:
    def __init__(self):
        """Initialise the orchestrator"""
        self.shared_data = shared_data
        self.actions = []
        self.standalone_actions = []
        self.failed_scans_count = 0
        self.network_scanner = None
        self.last_vuln_scan_time = datetime.min
        self.load_actions()
        actions_loaded = [action.__class__.__name__ for action in self.actions + self.standalone_actions]
        logger.info(f"Actions loaded: {actions_loaded}")
        logger.info(f"Standalone actions: {[a.__class__.__name__ for a in self.standalone_actions]}")
        logger.info(f"Port-based actions: {[a.__class__.__name__ for a in self.actions]}")
        self.semaphore = threading.Semaphore(10)

    def load_actions(self):
        """Load all actions from the actions file"""
        self.actions_dir = self.shared_data.actions_dir
        with open(self.shared_data.actions_file, 'r') as file:
            actions_config = json.load(file)
        for action in actions_config:
            module_name = action["b_module"]
            if module_name == 'scanning':
                self.load_scanner(module_name)
            elif module_name == 'nmap_vuln_scanner':
                self.load_nmap_vuln_scanner(module_name)
            else:
                self.load_action(module_name, action)

    def load_scanner(self, module_name):
        """Load the network scanner"""
        module = importlib.import_module(f'actions.{module_name}')
        b_class = getattr(module, 'b_class')
        self.network_scanner = getattr(module, b_class)(self.shared_data)

    def load_nmap_vuln_scanner(self, module_name):
        """Load the nmap vulnerability scanner"""
        self.nmap_vuln_scanner = NmapVulnScanner(self.shared_data)

    def load_action(self, module_name, action):
        """Load an action from the actions file"""
        module = importlib.import_module(f'actions.{module_name}')
        try:
            b_class = action["b_class"]
            action_instance = getattr(module, b_class)(self.shared_data)
            action_instance.action_name = b_class
            action_instance.b_parent_action = action.get("b_parent")

            # Cast port to int so "0" (string from JSON) and 0 (int) both route to standalone
            raw_port = action.get("b_port")
            try:
                action_instance.port = int(raw_port)
            except (TypeError, ValueError):
                action_instance.port = None

            if action_instance.port == 0:
                self.standalone_actions.append(action_instance)
                logger.debug(f"Loaded standalone action: {b_class}")
            else:
                self.actions.append(action_instance)
                logger.debug(f"Loaded port-based action: {b_class} on port {action_instance.port}")
        except AttributeError as e:
            logger.error(f"Module {module_name} is missing required attributes: {e}")

    def _parse_status_time(self, status_str, label):
        """Parse a timestamp from a status string like 'success_20240101_120000'."""
        try:
            parts = status_str.split('_')
            return datetime.strptime(parts[1] + "_" + parts[2], "%Y%m%d_%H%M%S")
        except (ValueError, IndexError) as e:
            logger.error(f"Error parsing {label} time from '{status_str}': {e}")
            return None

    def _check_retry_delay(self, status_str, action_name, delay_seconds, label):
        """Returns True if the action should be skipped due to retry delay."""
        last_time = self._parse_status_time(status_str, label)
        if last_time is None:
            return False
        next_run = last_time + timedelta(seconds=delay_seconds)
        if datetime.now() < next_run:
            remaining = int((next_run - datetime.now()).total_seconds())
            logger.warning(f"Skipping {action_name} due to {label} retry delay, retry in: {str(timedelta(seconds=remaining))}")
            return True
        return False

    def process_alive_ips(self, current_data):
        """Process all IPs with alive status set to 1"""
        any_action_executed = False

        for action in self.actions:
            for row in current_data:
                if row["Alive"] != '1':
                    continue
                ip = row["IPs"]
                ports = row["Ports"].split(';')
                action_key = action.action_name

                if action.b_parent_action is None:
                    with self.semaphore:
                        if self.execute_action(action, ip, ports, row, action_key, current_data):
                            any_action_executed = True
                            self.shared_data.bjornorch_status = action_key

                            for child_action in self.actions:
                                if child_action.b_parent_action == action_key:
                                    with self.semaphore:
                                        if self.execute_action(child_action, ip, ports, row, child_action.action_name, current_data):
                                            self.shared_data.bjornorch_status = child_action.action_name
                                            break
                            break

        for child_action in self.actions:
            if child_action.b_parent_action:
                action_key = child_action.action_name
                for row in current_data:
                    ip = row["IPs"]
                    ports = row["Ports"].split(';')
                    with self.semaphore:
                        if self.execute_action(child_action, ip, ports, row, action_key, current_data):
                            any_action_executed = True
                            self.shared_data.bjornorch_status = action_key
                            break

        return any_action_executed

    def execute_action(self, action, ip, ports, row, action_key, current_data):
        """Execute an action on a target"""
        if hasattr(action, 'port') and action.port is not None and str(action.port) not in ports:
            return False

        if action.b_parent_action:
            parent_status = row.get(action.b_parent_action, "")
            if 'success' not in parent_status:
                return False

        status_str = row.get(action_key, "")

        if 'success' in status_str:
            if not self.shared_data.retry_success_actions:
                return False
            if self._check_retry_delay(status_str, action.action_name, self.shared_data.success_retry_delay, 'success'):
                return False

        if 'failed' in status_str:
            if self._check_retry_delay(status_str, action.action_name, self.shared_data.failed_retry_delay, 'failed'):
                return False

        try:
            logger.info(f"Executing action {action.action_name} for {ip}:{action.port}")
            self.shared_data.bjornstatustext2 = ip
            result = action.execute(ip, str(action.port), row, action_key)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            row[action_key] = f'{result}_{timestamp}'
            self.shared_data.write_data(current_data)
            return result == 'success'
        except Exception as e:
            logger.error(f"Action {action.action_name} failed: {e}")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            row[action_key] = f'failed_{timestamp}'
            self.shared_data.write_data(current_data)
            return False

    def execute_standalone_action(self, action, current_data):
        """Execute a standalone action (no target IP required)"""
        row = next((r for r in current_data if r["MAC Address"] == "STANDALONE"), None)
        if not row:
            row = {
                "MAC Address": "STANDALONE",
                "IPs": "STANDALONE",
                "Hostnames": "STANDALONE",
                "Ports": "0",
                "Alive": "0"
            }
            current_data.append(row)

        action_key = action.action_name
        if action_key not in row:
            row[action_key] = ""

        status_str = row.get(action_key, "")

        if 'success' in status_str:
            if not self.shared_data.retry_success_actions:
                return False
            if self._check_retry_delay(status_str, action.action_name, self.shared_data.success_retry_delay, 'success'):
                return False

        if 'failed' in status_str:
            if self._check_retry_delay(status_str, action.action_name, self.shared_data.failed_retry_delay, 'failed'):
                return False

        try:
            logger.info(f"Executing standalone action {action.action_name}")
            self.shared_data.bjornorch_status = action.action_name
            result = action.execute()
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            row[action_key] = f'{result}_{timestamp}'
            if result == 'success':
                logger.info(f"Standalone action {action.action_name} executed successfully")
            else:
                logger.error(f"Standalone action {action.action_name} failed")
            self.shared_data.write_data(current_data)
            return result == 'success'
        except Exception as e:
            logger.error(f"Standalone action {action.action_name} failed: {e}")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            row[action_key] = f'failed_{timestamp}'
            self.shared_data.write_data(current_data)
            return False

    def run_standalone_actions(self, current_data):
        """Run all standalone actions every cycle, regardless of alive targets."""
        for action in self.standalone_actions:
            with self.semaphore:
                self.execute_standalone_action(action, current_data)

    def run_vuln_scans(self, current_data):
        """Run nmap vulnerability scans if enabled and interval has passed."""
        if not self.shared_data.scan_vuln_running:
            return
        current_time = datetime.now()
        if current_time < self.last_vuln_scan_time + timedelta(seconds=self.shared_data.scan_vuln_interval):
            return
        try:
            logger.info("Starting vulnerability scans...")
            for row in current_data:
                if row["Alive"] != '1':
                    continue
                ip = row["IPs"]
                scan_status = row.get("NmapVulnScanner", "")

                if 'success' in scan_status:
                    if not self.shared_data.retry_success_actions:
                        logger.warning(f"Skipping vuln scan for {ip}, retry on success disabled.")
                        continue
                    if self._check_retry_delay(scan_status, "NmapVulnScanner", self.shared_data.success_retry_delay, 'success'):
                        continue

                if 'failed' in scan_status:
                    if self._check_retry_delay(scan_status, "NmapVulnScanner", self.shared_data.failed_retry_delay, 'failed'):
                        continue

                with self.semaphore:
                    result = self.nmap_vuln_scanner.execute(ip, row, "NmapVulnScanner")
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    row["NmapVulnScanner"] = f'{result}_{timestamp}'
                    self.shared_data.write_data(current_data)

            self.last_vuln_scan_time = current_time
        except Exception as e:
            logger.error(f"Error during vulnerability scan: {e}")

    def run(self):
        """Run the orchestrator cycle to execute actions"""
        self.shared_data.bjornorch_status = "NetworkScanner"
        self.shared_data.bjornstatustext2 = "First scan..."
        self.network_scanner.scan()
        self.shared_data.bjornstatustext2 = ""

        while not self.shared_data.orchestrator_should_exit:
            current_data = self.shared_data.read_data()
            any_action_executed = False
            action_retry_pending = False

            # Run standalone actions every cycle (BLE, logging, etc.)
            self.run_standalone_actions(current_data)

            # Process alive IPs for port-based actions
            any_action_executed = self.process_alive_ips(current_data)

            # Second pass for port-based actions
            for action in self.actions:
                for row in current_data:
                    if row["Alive"] != '1':
                        continue
                    ip = row["IPs"]
                    ports = row["Ports"].split(';')
                    action_key = action.action_name

                    if action.b_parent_action is None:
                        with self.semaphore:
                            if self.execute_action(action, ip, ports, row, action_key, current_data):
                                any_action_executed = True
                                self.shared_data.bjornorch_status = action_key

                                for child_action in self.actions:
                                    if child_action.b_parent_action == action_key:
                                        with self.semaphore:
                                            if self.execute_action(child_action, ip, ports, row, child_action.action_name, current_data):
                                                self.shared_data.bjornorch_status = child_action.action_name
                                                break
                                break

            for child_action in self.actions:
                if child_action.b_parent_action:
                    action_key = child_action.action_name
                    for row in current_data:
                        ip = row["IPs"]
                        ports = row["Ports"].split(';')
                        with self.semaphore:
                            if self.execute_action(child_action, ip, ports, row, action_key, current_data):
                                any_action_executed = True
                                self.shared_data.bjornorch_status = action_key
                                break

            self.shared_data.write_data(current_data)

            if not any_action_executed:
                self.shared_data.bjornorch_status = "IDLE"
                self.shared_data.bjornstatustext2 = ""
                logger.info("No available targets. Running network scan...")

                if self.network_scanner:
                    self.shared_data.bjornorch_status = "NetworkScanner"
                    self.network_scanner.scan()
                    current_data = self.shared_data.read_data()
                    any_action_executed = self.process_alive_ips(current_data)
                    self.run_vuln_scans(current_data)
                else:
                    logger.warning("No network scanner available.")

                self.failed_scans_count += 1
                if self.failed_scans_count >= 1:
                    idle_start_time = datetime.now()
                    idle_end_time = idle_start_time + timedelta(seconds=self.shared_data.scan_interval)
                    while datetime.now() < idle_end_time:
                        if self.shared_data.orchestrator_should_exit:
                            break
                        remaining_time = int((idle_end_time - datetime.now()).total_seconds())
                        self.shared_data.bjornorch_status = "IDLE"
                        self.shared_data.bjornstatustext2 = ""
                        sys.stdout.write('\x1b[1A\x1b[2K')
                        logger.warning(f"No new targets found. Next scan in: {remaining_time}s")
                        time.sleep(1)
                    self.failed_scans_count = 0
                    continue
            else:
                self.failed_scans_count = 0
                action_retry_pending = True

            if action_retry_pending:
                self.failed_scans_count = 0


if __name__ == "__main__":
    orchestrator = Orchestrator()
    orchestrator.run()