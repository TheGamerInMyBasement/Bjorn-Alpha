#!/bin/bash

# BJORN Installation Script — Omega Edition
# Based on original by infinition, updated for TheGamerInMyBasement/Bjorn-Omega
# Adds: all required packages, sshpass, BT tools, vsftpd, getmac, python-nmap,
#       torch, torch-geometric, SMB, telnet replacement, auto chmod fixes

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

LOG_DIR="/var/log/bjorn_install"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/bjorn_install_$(date +%Y%m%d_%H%M%S).log"
VERBOSE=false

BJORN_USER="bjorn"
BJORN_PATH="/home/${BJORN_USER}/Bjorn"
CURRENT_STEP=0
TOTAL_STEPS=8

if [[ "$1" == "--help" ]]; then
    echo "Usage: sudo ./install_bjorn.sh"
    exit 0
fi

show_progress() {
    echo -e "${BLUE}Step $CURRENT_STEP of $TOTAL_STEPS: $1${NC}"
}

log() {
    local level=$1
    shift
    local message="[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $*"
    echo -e "$message" >> "$LOG_FILE"
    if [ "$VERBOSE" = true ] || [ "$level" != "DEBUG" ]; then
        case $level in
            "ERROR")   echo -e "${RED}$message${NC}" ;;
            "SUCCESS") echo -e "${GREEN}$message${NC}" ;;
            "WARNING") echo -e "${YELLOW}$message${NC}" ;;
            "INFO")    echo -e "${BLUE}$message${NC}" ;;
            *)         echo -e "$message" ;;
        esac
    fi
}

handle_error() {
    local error_code=$?
    local error_message=$1
    log "ERROR" "An error occurred during: $error_message (Error code: $error_code)"
    log "ERROR" "Check the log file for details: $LOG_FILE"
    echo -e "\n${RED}Would you like to:"
    echo "1. Retry this step"
    echo "2. Skip this step (not recommended)"
    echo "3. Exit installation${NC}"
    read -r choice
    case $choice in
        1) return 1 ;;
        2) return 0 ;;
        3) clean_exit 1 ;;
        *) handle_error "$error_message" ;;
    esac
}

check_success() {
    if [ $? -eq 0 ]; then
        log "SUCCESS" "$1"
        return 0
    else
        handle_error "$1"
        return $?
    fi
}

check_system_compatibility() {
    log "INFO" "Checking system compatibility..."
    local should_ask_confirmation=false

    # Check if running on Raspberry Pi
    if ! grep -q "Raspberry Pi" /proc/cpuinfo; then
        log "WARNING" "This system might not be a Raspberry Pi"
        should_ask_confirmation=true
    fi

    # Check RAM (Raspberry Pi Zero has 512MB RAM)
    total_ram=$(free -m | awk '/^Mem:/{print $2}')
    if [ "$total_ram" -lt 410 ]; then
        log "WARNING" "Low RAM detected. Required: 512MB (410 with OS running), Found: ${total_ram}MB"
        echo -e "${YELLOW}Your system has less RAM than recommended. This might affect performance.${NC}"
        should_ask_confirmation=true
    else
        log "SUCCESS" "RAM check passed: ${total_ram}MB available"
    fi

    # Check available disk space
    available_space=$(df -m /home | awk 'NR==2 {print $4}')
    if [ "$available_space" -lt 2048 ]; then
        log "WARNING" "Low disk space. Recommended: 2GB, Found: ${available_space}MB"
        echo -e "${YELLOW}Your system has less free space than recommended.${NC}"
        should_ask_confirmation=true
    else
        log "SUCCESS" "Disk space check passed: ${available_space}MB available"
    fi

    # Check OS version
    if [ -f "/etc/os-release" ]; then
        source /etc/os-release

        # Verify if it's Raspbian
        if [ "$NAME" != "Raspbian GNU/Linux" ]; then
            log "WARNING" "Different OS detected. Recommended: Raspbian GNU/Linux, Found: ${NAME}"
            echo -e "${YELLOW}Your system is not running Raspbian GNU/Linux.${NC}"
            should_ask_confirmation=true
        fi

        # Compare versions (expecting Bookworm = 12)
        expected_version="12"
        if [ "$VERSION_ID" != "$expected_version" ]; then
            log "WARNING" "Different OS version detected"
            echo -e "${YELLOW}This script was tested with Raspbian GNU/Linux 12 (bookworm)${NC}"
            echo -e "${YELLOW}Current system: ${PRETTY_NAME}${NC}"
            if [ "$VERSION_ID" -lt "$expected_version" ]; then
                echo -e "${YELLOW}Your system version ($VERSION_ID) is older than recommended ($expected_version)${NC}"
            elif [ "$VERSION_ID" -gt "$expected_version" ]; then
                echo -e "${YELLOW}Your system version ($VERSION_ID) is newer than tested ($expected_version)${NC}"
            fi
            should_ask_confirmation=true
        else
            log "SUCCESS" "OS version check passed: ${PRETTY_NAME}"
        fi
    else
        log "WARNING" "Could not determine OS version (/etc/os-release not found)"
        should_ask_confirmation=true
    fi

    # Check architecture
    architecture=$(dpkg --print-architecture)
    if [ "$architecture" != "armhf" ] && [ "$architecture" != "arm64" ]; then
        log "WARNING" "Different architecture detected. Expected: armhf or arm64, Found: ${architecture}"
        echo -e "${YELLOW}This script was tested with armhf/arm64 architecture${NC}"
        should_ask_confirmation=true
    else
        log "SUCCESS" "Architecture check passed: ${architecture}"
    fi

    # Additional Pi Zero specific checks
    if grep -q "Pi Zero" /proc/cpuinfo || grep -q "BCM2835" /proc/cpuinfo; then
        log "SUCCESS" "Raspberry Pi Zero detected"
    else
        log "WARNING" "Could not confirm this is a Raspberry Pi Zero"
        echo -e "${YELLOW}This script was designed for Raspberry Pi Zero${NC}"
        should_ask_confirmation=true
    fi

    if [ "$should_ask_confirmation" = true ]; then
        echo -e "\n${YELLOW}Some system compatibility warnings were detected (see above).${NC}"
        echo -e "${YELLOW}The installation might not work as expected.${NC}"
        echo -e "${YELLOW}Do you want to continue anyway? (y/n)${NC}"
        read -r response
        if [[ ! "$response" =~ ^[Yy]$ ]]; then
            log "INFO" "Installation aborted by user after compatibility warnings"
            clean_exit 1
        fi
    else
        log "SUCCESS" "All compatibility checks passed"
    fi

    log "INFO" "System compatibility check completed"
    return 0
}

install_dependencies() {
    log "INFO" "Installing system dependencies..."

    apt-get update

    # Core system packages
    apt_packages=(
        "python3-pip"
        "python3-dev"
        "python3-pil"
        "python3-numpy"
        "python3-paramiko"
        "python3-pymysql"
        "python3-sqlalchemy"
        "python3-requests"
        "python3-netifaces"
        "wget"
        "lsof"
        "git"
        "curl"
        "libopenjp2-7"
        "nmap"
        "libopenblas-dev"
        "libatlas-base-dev"
        "build-essential"
        "libffi-dev"
        "libssl-dev"
        "libgpiod-dev"
        "libi2c-dev"
        "libjpeg-dev"
        "zlib1g-dev"
        "libpng-dev"
        # Bluetooth
        "bluetooth"
        "bluez"
        "bluez-tools"
        # Network tools
        "sshpass"
        "smbclient"
        "wireless-tools"
        "iw"
        "net-tools"
        "arp-scan"
        "dhcpcd5"
        "bridge-utils"
        # FTP server (for payload deployment)
        "vsftpd"
        # Other
        "nmap"
    )

    for package in "${apt_packages[@]}"; do
        log "INFO" "Installing $package..."
        apt-get install -y "$package" >> "$LOG_FILE" 2>&1
        if [ $? -eq 0 ]; then
            log "SUCCESS" "Installed $package"
        else
            log "WARNING" "Failed to install $package — continuing"
        fi
    done

    nmap --script-updatedb >> "$LOG_FILE" 2>&1
    check_success "System dependencies installation completed"
}

install_python_packages() {
    log "INFO" "Installing Python packages via pip..."

    pip_packages=(
        "RPi.GPIO==0.7.1"
        "spidev==3.5"
        "Pillow==9.4.0"
        "numpy==2.1.3"
        "rich==13.9.4"
        "pandas==2.2.3"
        "netifaces==0.11.0"
        "ping3==4.0.8"
        "get-mac==0.9.2"
        "getmac"
        "paramiko==3.5.0"
        "smbprotocol==1.14.0"
        "pysmb==1.2.10"
        "pymysql==1.1.1"
        "sqlalchemy==2.0.36"
        "python-nmap==0.7.1"
        "impacket"
        "requests"
        "telnetlib3"
        "torch"
        "torch-geometric"
    )

    for package in "${pip_packages[@]}"; do
        log "INFO" "pip install $package..."
        pip3 install "$package" --break-system-packages >> "$LOG_FILE" 2>&1
        if [ $? -eq 0 ]; then
            log "SUCCESS" "Installed $package"
        else
            log "WARNING" "Failed to install $package — continuing"
        fi
    done

    check_success "Python packages installation completed"
}

configure_system_limits() {
    log "INFO" "Configuring system limits..."

    cat >> /etc/security/limits.conf << EOF
* soft nofile 65535
* hard nofile 65535
root soft nofile 65535
root hard nofile 65535
EOF

    sed -i '/^#DefaultLimitNOFILE=/d' /etc/systemd/system.conf
    echo "DefaultLimitNOFILE=65535" >> /etc/systemd/system.conf
    sed -i '/^#DefaultLimitNOFILE=/d' /etc/systemd/user.conf
    echo "DefaultLimitNOFILE=65535" >> /etc/systemd/user.conf

    cat > /etc/security/limits.d/90-nofile.conf << EOF
root soft nofile 65535
root hard nofile 65535
EOF

    echo "fs.file-max = 2097152" >> /etc/sysctl.conf
    sysctl -p >> "$LOG_FILE" 2>&1

    check_success "System limits configuration completed"
}

configure_interfaces() {
    log "INFO" "Configuring SPI and I2C interfaces..."
    raspi-config nonint do_spi 0
    raspi-config nonint do_i2c 0
    check_success "Interface configuration completed"
}

setup_bjorn() {
    log "INFO" "Setting up BJORN (Omega fork)..."

    # Create BJORN user if it doesn't exist
    if ! id -u $BJORN_USER >/dev/null 2>&1; then
        adduser --disabled-password --gecos "" $BJORN_USER
        check_success "Created BJORN user"
    fi

    cd /home/$BJORN_USER

    if [ -d "Bjorn" ]; then
        log "INFO" "Bjorn directory already exists — pulling latest"
        cd Bjorn
        git pull >> "$LOG_FILE" 2>&1
    else
        log "INFO" "Cloning Bjorn-Omega repository as 'Bjorn'..."
        git clone https://github.com/TheGamerInMyBasement/Bjorn-Omega.git Bjorn
        check_success "Cloned Bjorn-Omega repository"
        cd Bjorn
    fi

    # Update EPD type in config
    if [ -f "config/shared_config.json" ]; then
        sed -i "s/\"epd_type\": \"[^\"]*\"/\"epd_type\": \"$EPD_VERSION\"/" config/shared_config.json
        log "SUCCESS" "Updated E-Paper display config to $EPD_VERSION"
    else
        log "WARNING" "config/shared_config.json not found — skipping EPD config"
    fi

    # Install requirements.txt if present
    if [ -f "requirements.txt" ]; then
        log "INFO" "Installing requirements.txt..."
        pip3 install -r requirements.txt --break-system-packages >> "$LOG_FILE" 2>&1
        check_success "Installed requirements.txt"
    fi

    # Create payloads directory
    mkdir -p "$BJORN_PATH/payloads"
    log "SUCCESS" "Created payloads directory"

    # Set permissions
    chown -R $BJORN_USER:$BJORN_USER /home/$BJORN_USER/Bjorn
    chmod -R 755 /home/$BJORN_USER/Bjorn

    # Add bjorn user to groups
    usermod -a -G spi,gpio,i2c,bluetooth $BJORN_USER
    check_success "Setup completed"
}

setup_services() {
    log "INFO" "Setting up system services..."

    # Create kill_port_8000.sh — persistent, won't need manual chmod again
    cat > $BJORN_PATH/kill_port_8000.sh << 'EOF'
#!/bin/bash
PORT=8000
PIDS=$(lsof -t -i:$PORT 2>/dev/null)
if [ -n "$PIDS" ]; then
    echo "Killing PIDs using port $PORT: $PIDS"
    kill -9 $PIDS 2>/dev/null
fi
exit 0
EOF
    # Set executable and lock it so it stays that way
    chmod +x $BJORN_PATH/kill_port_8000.sh
    chown root:root $BJORN_PATH/kill_port_8000.sh
    log "SUCCESS" "Created and chmodded kill_port_8000.sh"

    # Create bjorn.service
    cat > /etc/systemd/system/bjorn.service << EOF
[Unit]
Description=Bjorn Service
DefaultDependencies=no
Before=basic.target
After=local-fs.target

[Service]
ExecStartPre=/bin/chmod +x /home/bjorn/Bjorn/kill_port_8000.sh
ExecStartPre=/home/bjorn/Bjorn/kill_port_8000.sh
ExecStart=/usr/bin/python3 /home/bjorn/Bjorn/Bjorn.py
WorkingDirectory=/home/bjorn/Bjorn
StandardOutput=inherit
StandardError=inherit
Restart=always
RestartSec=5
User=root

# Monitor file descriptors and restart if limit approached
ExecStartPost=/bin/bash -c 'FILE_LIMIT=\$(ulimit -n); THRESHOLD=\$(( FILE_LIMIT - 1000 )); while :; do TOTAL_OPEN_FILES=\$(lsof 2>/dev/null | wc -l); if [ "\$TOTAL_OPEN_FILES" -ge "\$THRESHOLD" ]; then echo "FD threshold reached: \$TOTAL_OPEN_FILES. Restarting."; systemctl restart bjorn.service; exit 0; fi; sleep 10; done &'

[Install]
WantedBy=multi-user.target
EOF

    # PAM limits
    grep -q "pam_limits.so" /etc/pam.d/common-session || \
        echo "session required pam_limits.so" >> /etc/pam.d/common-session
    grep -q "pam_limits.so" /etc/pam.d/common-session-noninteractive || \
        echo "session required pam_limits.so" >> /etc/pam.d/common-session-noninteractive

    systemctl daemon-reload
    systemctl enable bjorn.service
    check_success "Services setup completed"
}

configure_usb_gadget() {
    log "INFO" "Configuring USB Gadget..."

    sed -i 's/rootwait/rootwait modules-load=dwc2,g_ether/' /boot/firmware/cmdline.txt
    echo "dtoverlay=dwc2" >> /boot/firmware/config.txt

    cat > /usr/local/bin/usb-gadget.sh << 'EOF'
#!/bin/bash
set -e
modprobe libcomposite
cd /sys/kernel/config/usb_gadget/
mkdir -p g1
cd g1
echo 0x1d6b > idVendor
echo 0x0104 > idProduct
echo 0x0100 > bcdDevice
echo 0x0200 > bcdUSB
mkdir -p strings/0x409
echo "fedcba9876543210" > strings/0x409/serialnumber
echo "Raspberry Pi"     > strings/0x409/manufacturer
echo "Pi Zero USB"      > strings/0x409/product
mkdir -p configs/c.1/strings/0x409
echo "Config 1: ECM network" > configs/c.1/strings/0x409/configuration
echo 250 > configs/c.1/MaxPower
mkdir -p functions/ecm.usb0
[ -L configs/c.1/ecm.usb0 ] && rm configs/c.1/ecm.usb0
ln -s functions/ecm.usb0 configs/c.1/
max_retries=10
retry_count=0
while ! ls /sys/class/udc > UDC 2>/dev/null; do
    [ $retry_count -ge $max_retries ] && { echo "UDC busy after $max_retries attempts."; exit 1; }
    retry_count=$((retry_count + 1))
    sleep 1
done
ip addr show usb0 | grep -q "172.20.2.1" || ifconfig usb0 172.20.2.1 netmask 255.255.255.0
EOF

    chmod +x /usr/local/bin/usb-gadget.sh

    cat > /etc/systemd/system/usb-gadget.service << EOF
[Unit]
Description=USB Gadget Service
After=network.target

[Service]
ExecStartPre=/sbin/modprobe libcomposite
ExecStart=/usr/local/bin/usb-gadget.sh
Type=simple
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

    grep -q "allow-hotplug usb0" /etc/network/interfaces || cat >> /etc/network/interfaces << EOF

allow-hotplug usb0
iface usb0 inet static
    address 172.20.2.1
    netmask 255.255.255.0
EOF

    systemctl daemon-reload
    systemctl enable systemd-networkd
    systemctl enable usb-gadget
    systemctl start systemd-networkd
    systemctl start usb-gadget 2>/dev/null || true

    check_success "USB Gadget configuration completed"
}

verify_installation() {
    log "INFO" "Verifying installation..."

    # Verify kill script is executable
    if [ -x "$BJORN_PATH/kill_port_8000.sh" ]; then
        log "SUCCESS" "kill_port_8000.sh is executable"
    else
        chmod +x "$BJORN_PATH/kill_port_8000.sh"
        log "WARNING" "kill_port_8000.sh was not executable — fixed"
    fi

    if systemctl is-active --quiet bjorn.service; then
        log "SUCCESS" "BJORN service is running"
    else
        log "WARNING" "BJORN service is not running yet (will start after reboot)"
    fi

    sleep 3
    if curl -s http://localhost:8000 > /dev/null 2>&1; then
        log "SUCCESS" "Web interface is accessible at http://localhost:8000"
    else
        log "INFO" "Web interface not responding yet — normal before reboot"
    fi

    # Test key python imports
    log "INFO" "Testing key Python imports..."
    cd $BJORN_PATH
    python3 -c "import nmap; print('nmap OK')"           >> "$LOG_FILE" 2>&1 && log "SUCCESS" "python-nmap OK" || log "WARNING" "python-nmap import failed"
    python3 -c "import getmac; print('getmac OK')"       >> "$LOG_FILE" 2>&1 && log "SUCCESS" "getmac OK"     || log "WARNING" "getmac import failed"
    python3 -c "import paramiko; print('paramiko OK')"   >> "$LOG_FILE" 2>&1 && log "SUCCESS" "paramiko OK"   || log "WARNING" "paramiko import failed"
    python3 -c "import rich; print('rich OK')"           >> "$LOG_FILE" 2>&1 && log "SUCCESS" "rich OK"       || log "WARNING" "rich import failed"
}

clean_exit() {
    local exit_code=$1
    if [ $exit_code -eq 0 ]; then
        log "SUCCESS" "BJORN installation completed successfully!"
    else
        log "ERROR" "BJORN installation failed! Check: $LOG_FILE"
    fi
    exit $exit_code
}

main() {
    log "INFO" "Starting BJORN Omega installation..."

    if [ "$(id -u)" -ne 0 ]; then
        echo "Run as root: sudo ./install_bjorn.sh"
        exit 1
    fi

    echo -e "${BLUE}BJORN Installation Options:${NC}"
    echo "1. Full installation (recommended)"
    echo "2. Custom installation"
    read -p "Choose an option (1/2): " install_option

    echo -e "\n${BLUE}Select your E-Paper Display version:${NC}"
    echo "1. epd2in13"
    echo "2. epd2in13_V2"
    echo "3. epd2in13_V3"
    echo "4. epd2in13_V4"
    echo "5. epd2in7"
    while true; do
        read -p "Enter choice (1-5): " epd_choice
        case $epd_choice in
            1) EPD_VERSION="epd2in13";    break ;;
            2) EPD_VERSION="epd2in13_V2"; break ;;
            3) EPD_VERSION="epd2in13_V3"; break ;;
            4) EPD_VERSION="epd2in13_V4"; break ;;
            5) EPD_VERSION="epd2in7";     break ;;
            *) echo -e "${RED}Invalid choice.${NC}" ;;
        esac
    done
    log "INFO" "Selected E-Paper: $EPD_VERSION"

    case $install_option in
        1)
            CURRENT_STEP=1; show_progress "Checking system compatibility"
            check_system_compatibility

            CURRENT_STEP=2; show_progress "Installing system dependencies"
            install_dependencies

            CURRENT_STEP=3; show_progress "Installing Python packages"
            install_python_packages

            CURRENT_STEP=4; show_progress "Configuring system limits"
            configure_system_limits

            CURRENT_STEP=5; show_progress "Configuring interfaces"
            configure_interfaces

            CURRENT_STEP=6; show_progress "Setting up BJORN"
            setup_bjorn

            CURRENT_STEP=7; show_progress "Configuring USB Gadget"
            configure_usb_gadget

            CURRENT_STEP=8; show_progress "Setting up services"
            setup_services

            show_progress "Verifying installation"
            verify_installation
            ;;
        2)
            echo "Custom installation — select components:"
            read -p "Check compatibility? (y/n): "    do_compat
            read -p "Install apt dependencies? (y/n): " do_deps
            read -p "Install pip packages? (y/n): "   do_pip
            read -p "Configure system limits? (y/n): " do_limits
            read -p "Configure interfaces? (y/n): "   do_iface
            read -p "Setup BJORN? (y/n): "            do_bjorn
            read -p "Configure USB Gadget? (y/n): "   do_usb
            read -p "Setup services? (y/n): "         do_svc

            [ "$do_compat"  = "y" ] && check_system_compatibility
            [ "$do_deps"    = "y" ] && install_dependencies
            [ "$do_pip"     = "y" ] && install_python_packages
            [ "$do_limits"  = "y" ] && configure_system_limits
            [ "$do_iface"   = "y" ] && configure_interfaces
            [ "$do_bjorn"   = "y" ] && setup_bjorn
            [ "$do_usb"     = "y" ] && configure_usb_gadget
            [ "$do_svc"     = "y" ] && setup_services
            verify_installation
            ;;
        *)
            log "ERROR" "Invalid option"
            clean_exit 1
            ;;
    esac

    # Remove git metadata
    find "$BJORN_PATH" -name ".git*" -exec rm -rf {} + 2>/dev/null || true

    log "SUCCESS" "BJORN Omega installation completed!"
    echo -e "\n${GREEN}Installation complete!${NC}"
    echo -e "${YELLOW}Notes:${NC}"
    echo "1. kill_port_8000.sh is auto-chmodded by the service — no manual fix needed"
    echo "2. Windows USB gadget: set static IP 172.20.2.2, mask 255.255.255.0, GW 172.20.2.1"
    echo "3. Web interface: http://[device-ip]:8000"
    echo "4. Log: $LOG_FILE"

    read -p "Reboot now? (y/n): " reboot_now
    if [ "$reboot_now" = "y" ]; then
        reboot
    else
        echo -e "${YELLOW}Reboot when ready to start Bjorn.${NC}"
    fi
}

main