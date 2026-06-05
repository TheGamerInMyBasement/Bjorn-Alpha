# orchestrator.py — Bjorn research edition
# Changes vs original:
#   - Import timeout wrapper so a hanging module never freezes startup
#   - Scanner None guard — runs without scanning if scanner fails to load
#   - All children run when parent succeeds (no break after first child)
#   - Child sweep: if parent hasn't run yet, run parent first then child
#   - Random idle action picker when no targets available
#   - Safe row.get() throughout (no KeyError on new actions)
#   - Semaphore lowered to 3 for Pi Zero
#   - All load_* wrapped in try/except so one bad module never kills startup

import json
import importlib
import random
import time
import logging
import sys
import threading
from datetime import datetime, timedelta
from actions.nmap_vuln_scanner import NmapVulnScanner
from init_shared import shared_data
from logger import Logger

logger = Logger(name="orchestrator.py", level=logging.DEBUG)


def _import_with_timeout(module_path, timeout=10):
    """Import a module in a thread with a timeout. Returns module or None."""
    result = [None]
    error  = [None]

    def _do_import():
        try:
            result[0] = importlib.import_module(module_path)
        except Exception as e:
            error[0] = e

    t = threading.Thread(target=_do_import, daemon=True)
    t.start()
    t.join(timeout)

    if t.is_alive():
        logger.error(f"Import of {module_path} timed out after {timeout}s — skipping")
        return None
    if error[0]:
        logger.error(f"Import of {module_path} failed: {error[0]}")
        return None
    return result[0]


class Orchestrator:
    def __init__(self):
        self.shared_data         = shared_data
        self.actions             = []
        self.standalone_actions  = []
        self.failed_scans_count  = 0
        self.network_scanner     = None
        self.nmap_vuln_scanner   = None
        self.last_vuln_scan_time = datetime.min
        self.load_actions()
        actions_loaded = [a.__class__.__name__ for a in self.actions + self.standalone_actions]
        logger.info(f"Actions loaded: {actions_loaded}")
        self.semaphore = threading.Semaphore(3)

    # ------------------------------------------------------------------ #
    # Loading
    # ------------------------------------------------------------------ #

    def load_actions(self):
        self.actions_dir = self.shared_data.actions_dir
        try:
            with open(self.shared_data.actions_file, 'r') as f:
                actions_config = json.load(f)
        except Exception as e:
            logger.error(f"Failed to read actions file: {e}")
            return

        for action in actions_config:
            module_name = action.get("b_module")
            if not module_name:
                continue
            if module_name == 'scanning':
                self.load_scanner(module_name)
            elif module_name == 'nmap_vuln_scanner':
                self.load_nmap_vuln_scanner(module_name)
            else:
                self.load_action(module_name, action)

    def load_scanner(self, module_name):
        logger.info(f"Loading network scanner: {module_name}")
        module = _import_with_timeout(f'actions.{module_name}', timeout=15)
        if module is None:
            logger.error("Network scanner import failed or timed out — will run scan-less")
            self.network_scanner = None
            return
        try:
            b_class = getattr(module, 'b_class')
            self.network_scanner = getattr(module, b_class)(self.shared_data)
            logger.info(f"Network scanner loaded: {b_class}")
        except Exception as e:
            logger.error(f"Failed to instantiate network scanner: {e}")
            self.network_scanner = None

    def load_nmap_vuln_scanner(self, module_name):
        try:
            self.nmap_vuln_scanner = NmapVulnScanner(self.shared_data)
        except Exception as e:
            logger.error(f"Failed to load nmap vuln scanner: {e}")
            self.nmap_vuln_scanner = None

    def load_action(self, module_name, action):
        module = _import_with_timeout(f'actions.{module_name}', timeout=10)
        if module is None:
            return
        try:
            b_class  = action["b_class"]
            instance = getattr(module, b_class)(self.shared_data)
            instance.action_name     = b_class
            instance.port            = action.get("b_port")
            instance.b_parent_action = action.get("b_parent")
            if instance.port == 0:
                self.standalone_actions.append(instance)
            else:
                self.actions.append(instance)
        except Exception as e:
            logger.error(f"Module {module_name} failed to load: {e}")

    # ------------------------------------------------------------------ #
    # Execution gate
    # ------------------------------------------------------------------ #

    def execute_action(self, action, ip, ports, row, action_key, current_data):
        """Gate checks then executes. Returns True only on success."""
        if hasattr(action, 'port') and str(action.port) not in ports:
            return False

        if action.b_parent_action:
            if 'success' not in row.get(action.b_parent_action, ''):
                return False

        current_status = row.get(action_key, '')

        if 'success' in current_status:
            if not self.shared_data.retry_success_actions:
                return False
            try:
                last_ok = datetime.strptime(
                    current_status.split('_')[1] + '_' + current_status.split('_')[2],
                    '%Y%m%d_%H%M%S')
                if datetime.now() < last_ok + timedelta(seconds=self.shared_data.success_retry_delay):
                    remaining = (last_ok + timedelta(seconds=self.shared_data.success_retry_delay) - datetime.now()).seconds
                    logger.warning(f"Skipping {action.action_name} for {ip}:{action.port} (success delay), retry in {timedelta(seconds=remaining)}")
                    return False
            except ValueError as e:
                logger.error(f"Error parsing success time for {action.action_name}: {e}")

        if 'failed' in current_status:
            try:
                last_fail = datetime.strptime(
                    current_status.split('_')[1] + '_' + current_status.split('_')[2],
                    '%Y%m%d_%H%M%S')
                if datetime.now() < last_fail + timedelta(seconds=self.shared_data.failed_retry_delay):
                    remaining = (last_fail + timedelta(seconds=self.shared_data.failed_retry_delay) - datetime.now()).seconds
                    logger.warning(f"Skipping {action.action_name} for {ip}:{action.port} (failed delay), retry in {timedelta(seconds=remaining)}")
                    return False
            except ValueError as e:
                logger.error(f"Error parsing failed time for {action.action_name}: {e}")

        try:
            logger.info(f"Executing {action.action_name} on {ip}:{action.port}")
            self.shared_data.bjornstatustext2 = ip
            result    = action.execute(ip, str(action.port), row, action_key)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            row[action_key] = f'{"success" if result == "success" else "failed"}_{timestamp}'
            self.shared_data.write_data(current_data)
            return result == 'success'
        except Exception as e:
            logger.error(f"Action {action.action_name} raised exception: {e}")
            row[action_key] = f'failed_{datetime.now().strftime("%Y%m%d_%H%M%S")}'
            self.shared_data.write_data(current_data)
            return False

    def execute_standalone_action(self, action, current_data):
        """Execute a standalone (port=0) action."""
        row = next((r for r in current_data if r["MAC Address"] == "STANDALONE"), None)
        if not row:
            row = {"MAC Address": "STANDALONE", "IPs": "STANDALONE",
                   "Hostnames": "STANDALONE", "Ports": "0", "Alive": "0"}
            current_data.append(row)

        action_key     = action.action_name
        current_status = row.get(action_key, '')

        if 'success' in current_status:
            if not self.shared_data.retry_success_actions:
                return False
            try:
                last_ok = datetime.strptime(
                    current_status.split('_')[1] + '_' + current_status.split('_')[2],
                    '%Y%m%d_%H%M%S')
                if datetime.now() < last_ok + timedelta(seconds=self.shared_data.success_retry_delay):
                    remaining = (last_ok + timedelta(seconds=self.shared_data.success_retry_delay) - datetime.now()).seconds
                    logger.warning(f"Skipping standalone {action.action_name} (success delay), retry in {timedelta(seconds=remaining)}")
                    return False
            except ValueError as e:
                logger.error(f"Error parsing success time: {e}")

        if 'failed' in current_status:
            try:
                last_fail = datetime.strptime(
                    current_status.split('_')[1] + '_' + current_status.split('_')[2],
                    '%Y%m%d_%H%M%S')
                if datetime.now() < last_fail + timedelta(seconds=self.shared_data.failed_retry_delay):
                    remaining = (last_fail + timedelta(seconds=self.shared_data.failed_retry_delay) - datetime.now()).seconds
                    logger.warning(f"Skipping standalone {action.action_name} (failed delay), retry in {timedelta(seconds=remaining)}")
                    return False
            except ValueError as e:
                logger.error(f"Error parsing failed time: {e}")

        try:
            logger.info(f"Executing standalone {action.action_name}")
            result    = action.execute()
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            if result == 'success':
                row[action_key] = f'success_{timestamp}'
                logger.info(f"Standalone {action.action_name} succeeded")
            else:
                row[action_key] = f'failed_{timestamp}'
                logger.error(f"Standalone {action.action_name} failed")
            self.shared_data.write_data(current_data)
            return result == 'success'
        except Exception as e:
            logger.error(f"Standalone {action.action_name} raised exception: {e}")
            row[action_key] = f'failed_{datetime.now().strftime("%Y%m%d_%H%M%S")}'
            self.shared_data.write_data(current_data)
            return False

    # ------------------------------------------------------------------ #
    # Smart execute — if child needs parent, run parent first
    # ------------------------------------------------------------------ #

    def _smart_execute(self, action, ip, ports, row, current_data):
        """
        Try to run an action. If it has a parent that hasn't succeeded yet,
        run the parent first then retry the child. This means a child action
        will never silently skip just because its parent hasn't run yet.
        """
        if action.b_parent_action:
            parent_status = row.get(action.b_parent_action, '')
            if 'success' not in parent_status:
                # Find and run the parent first
                parent = next(
                    (a for a in self.actions if a.action_name == action.b_parent_action),
                    None
                )
                if parent:
                    logger.info(f"Child {action.action_name} needs parent {action.b_parent_action} — running parent first on {ip}")
                    with self.semaphore:
                        parent_result = self.execute_action(
                            parent, ip, ports, row, parent.action_name, current_data
                        )
                    if parent_result:
                        logger.info(f"Parent {parent.action_name} succeeded — now running child {action.action_name}")
                    else:
                        logger.info(f"Parent {parent.action_name} failed/skipped — cannot run child {action.action_name}")
                        return False

        with self.semaphore:
            return self.execute_action(action, ip, ports, row, action.action_name, current_data)

    # ------------------------------------------------------------------ #
    # Child cascade — runs ALL children when parent succeeds
    # ------------------------------------------------------------------ #

    def _run_all_children(self, parent_key, ip, ports, row, current_data):
        """Run every child of parent_key. No early exit — all children get a turn."""
        for child in self.actions:
            if child.b_parent_action != parent_key:
                continue
            with self.semaphore:
                if self.execute_action(child, ip, ports, row, child.action_name, current_data):
                    self.shared_data.bjornorch_status = child.action_name
                    logger.info(f"  Child {child.action_name} succeeded on {ip}")
                else:
                    logger.info(f"  Child {child.action_name} skipped/failed on {ip}")

    # ------------------------------------------------------------------ #
    # Main dispatch
    # ------------------------------------------------------------------ #

    def process_alive_ips(self, current_data):
        any_action_executed = False

        # Pass 1: parent actions — on success immediately cascade all children
        for action in self.actions:
            if action.b_parent_action is not None:
                continue
            for row in current_data:
                if row["Alive"] != '1':
                    continue
                ip    = row["IPs"]
                ports = row["Ports"].split(';')
                with self.semaphore:
                    if self.execute_action(action, ip, ports, row, action.action_name, current_data):
                        any_action_executed = True
                        self.shared_data.bjornorch_status = action.action_name
                        logger.info(f"Parent {action.action_name} succeeded on {ip} — cascading to all children")
                        self._run_all_children(action.action_name, ip, ports, row, current_data)

        # Pass 2: child sweep — uses smart execute so parent runs first if needed
        for child in self.actions:
            if child.b_parent_action is None:
                continue
            for row in current_data:
                if row["Alive"] != '1':
                    continue
                ip    = row["IPs"]
                ports = row["Ports"].split(';')
                if self._smart_execute(child, ip, ports, row, current_data):
                    any_action_executed = True
                    self.shared_data.bjornorch_status = child.action_name

        return any_action_executed

    # ------------------------------------------------------------------ #
    # Random idle action — picks any eligible (host, action) at random
    # ------------------------------------------------------------------ #

    def _try_random_action(self, current_data):
        candidates = []
        for action in self.actions:
            for row in current_data:
                if row["Alive"] != '1':
                    continue
                ip    = row["IPs"]
                ports = row["Ports"].split(';')
                if hasattr(action, 'port') and str(action.port) not in ports:
                    continue
                if action.b_parent_action:
                    if 'success' not in row.get(action.b_parent_action, ''):
                        continue
                status = row.get(action.action_name, '')
                if 'success' in status and not self.shared_data.retry_success_actions:
                    continue
                if 'success' in status:
                    try:
                        last_ok = datetime.strptime(
                            status.split('_')[1] + '_' + status.split('_')[2], '%Y%m%d_%H%M%S')
                        if datetime.now() < last_ok + timedelta(seconds=self.shared_data.success_retry_delay):
                            continue
                    except ValueError:
                        pass
                if 'failed' in status:
                    try:
                        last_fail = datetime.strptime(
                            status.split('_')[1] + '_' + status.split('_')[2], '%Y%m%d_%H%M%S')
                        if datetime.now() < last_fail + timedelta(seconds=self.shared_data.failed_retry_delay):
                            continue
                    except ValueError:
                        pass
                candidates.append((action, row))

        if not candidates:
            logger.info("Idle random: no eligible candidates found.")
            return False

        action, row = random.choice(candidates)
        ip    = row["IPs"]
        ports = row["Ports"].split(';')
        logger.info(f"Idle: randomly picked {action.action_name} on {ip}")
        with self.semaphore:
            if self.execute_action(action, ip, ports, row, action.action_name, current_data):
                self.shared_data.bjornorch_status = action.action_name
                self._run_all_children(action.action_name, ip, ports, row, current_data)
                return True
        return False

    # ------------------------------------------------------------------ #
    # Vuln scan helper
    # ------------------------------------------------------------------ #

    def _run_vuln_scans(self, current_data):
        if self.nmap_vuln_scanner is None:
            return
        current_time = datetime.now()
        if current_time < self.last_vuln_scan_time + timedelta(seconds=self.shared_data.scan_vuln_interval):
            return
        try:
            logger.info("Starting vulnerability scans...")
            for row in current_data:
                if row.get("Alive") != '1':
                    continue
                ip          = row["IPs"]
                scan_status = row.get("NmapVulnScanner", "")

                if 'success' in scan_status:
                    if not self.shared_data.retry_success_actions:
                        continue
                    try:
                        last_ok = datetime.strptime(
                            scan_status.split('_')[1] + '_' + scan_status.split('_')[2], '%Y%m%d_%H%M%S')
                        if datetime.now() < last_ok + timedelta(seconds=self.shared_data.success_retry_delay):
                            continue
                    except ValueError:
                        pass

                if 'failed' in scan_status:
                    try:
                        last_fail = datetime.strptime(
                            scan_status.split('_')[1] + '_' + scan_status.split('_')[2], '%Y%m%d_%H%M%S')
                        if datetime.now() < last_fail + timedelta(seconds=self.shared_data.failed_retry_delay):
                            continue
                    except ValueError:
                        pass

                with self.semaphore:
                    result    = self.nmap_vuln_scanner.execute(ip, row, "NmapVulnScanner")
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    row["NmapVulnScanner"] = f'{"success" if result == "success" else "failed"}_{timestamp}'
                    self.shared_data.write_data(current_data)

            self.last_vuln_scan_time = current_time
        except Exception as e:
            logger.error(f"Error during vulnerability scan: {e}")

    # ------------------------------------------------------------------ #
    # Main loop
    # ------------------------------------------------------------------ #

    def run(self):
        if self.network_scanner is None:
            logger.error("Network scanner not loaded — running without scanning.")
            logger.error("Install missing packages: pip3 install getmac python-nmap --break-system-packages")
        else:
            self.shared_data.bjornorch_status = "NetworkScanner"
            self.shared_data.bjornstatustext2 = "First scan..."
            self.network_scanner.scan()
            self.shared_data.bjornstatustext2 = ""

        while not self.shared_data.orchestrator_should_exit:
            current_data        = self.shared_data.read_data()
            any_action_executed = self.process_alive_ips(current_data)
            self.shared_data.write_data(current_data)

            if not any_action_executed:
                self.shared_data.bjornorch_status = "IDLE"
                self.shared_data.bjornstatustext2 = ""
                logger.info("No actions executed — running network scan...")

                if self.network_scanner:
                    self.shared_data.bjornorch_status = "NetworkScanner"
                    self.network_scanner.scan()
                    current_data        = self.shared_data.read_data()
                    any_action_executed = self.process_alive_ips(current_data)
                    if self.shared_data.scan_vuln_running:
                        self._run_vuln_scans(current_data)
                else:
                    logger.warning("No network scanner available — skipping scan.")

                if not any_action_executed:
                    logger.info("Attempting random idle action...")
                    any_action_executed = self._try_random_action(current_data)

                self.failed_scans_count += 1
                if self.failed_scans_count >= 1:
                    for action in self.standalone_actions:
                        with self.semaphore:
                            if self.execute_standalone_action(action, current_data):
                                self.failed_scans_count = 0
                                break

                    idle_end = datetime.now() + timedelta(seconds=self.shared_data.scan_interval)
                    while datetime.now() < idle_end:
                        if self.shared_data.orchestrator_should_exit:
                            break
                        remaining = int((idle_end - datetime.now()).total_seconds())
                        self.shared_data.bjornorch_status = "IDLE"
                        self.shared_data.bjornstatustext2 = ""
                        sys.stdout.write('\x1b[1A\x1b[2K')
                        logger.warning(f"No new targets. Next scan in: {remaining} seconds")
                        time.sleep(1)
                    self.failed_scans_count = 0
                    continue
            else:
                self.failed_scans_count = 0


if __name__ == "__main__":
    orchestrator = Orchestrator()
    orchestrator.run()