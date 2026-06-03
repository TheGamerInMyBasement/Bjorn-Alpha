#!/bin/bash
# unsecure_ftp.sh
# Install and enable vsftpd FTP server on port 21

set -e

echo "==> Installing vsftpd"
sudo apt update
sudo apt install -y vsftpd

echo "==> Backing up config"
sudo cp /etc/vsftpd.conf /etc/vsftpd.conf.bak

echo "==> Configuring FTP server"

sudo bash -c 'cat > /etc/vsftpd.conf <<EOF
listen=YES
listen_ipv6=NO
anonymous_enable=NO
local_enable=YES
write_enable=YES
local_umask=022
dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
connect_from_port_20=YES
chroot_local_user=YES
allow_writeable_chroot=YES
pam_service_name=vsftpd
rsa_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem
rsa_private_key_file=/etc/ssl/private/ssl-cert-snakeoil.key
ssl_enable=NO
EOF'

echo "==> Enabling vsftpd service"
sudo systemctl enable vsftpd
sudo systemctl restart vsftpd

echo "==> FTP server is now running on port 21 forever."
echo "==> It will auto-start on boot and restart if it crashes."

