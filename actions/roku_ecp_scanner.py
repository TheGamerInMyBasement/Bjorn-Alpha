# roku_ecp_scanner.py
# Detects Roku devices on the network and checks if ECP (port 8060) is enabled.
# ECP is Roku's documented External Control Protocol — a public REST API
# intentionally exposed for remote control by official apps and integrations.
# Docs: https://developer.roku.com/docs/developer-program/dev-tools/external-control-api.md

import socket
import requests
import logging
import xml.etree.ElementTree as ET
from logger import Logger
from ntfy import send_ntfy

logger = Logger(name="roku_ecp_scanner.py", level=logging.DEBUG)

b_class  = "RokuECPScanner"
b_module = "roku_ecp_scanner"
b_status = "roku_ecp_scanner"
b_parent = None
b_port   = 8060

ECP_TIMEOUT = 5  # seconds


class RokuECPScanner:
    """
    Checks if a host has Roku ECP enabled on port 8060.
    Queries /query/device-info to confirm it's actually a Roku
    and pulls basic device info if so.
    """

    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.b_parent    = b_parent
        self.b_port      = b_port
        self.b_class     = b_class
        self.b_module    = b_module
        self.b_status    = b_status
        logger.info("RokuECPScanner initialized")

    def _query_ecp(self, ip, endpoint):
        """Query a Roku ECP endpoint. Returns response text or None."""
        url = f"http://{ip}:8060{endpoint}"
        try:
            resp = requests.get(url, timeout=ECP_TIMEOUT)
            if resp.status_code == 200:
                return resp.text
        except requests.exceptions.ConnectionError:
            pass
        except requests.exceptions.Timeout:
            logger.warning(f"Timeout querying {url}")
        except Exception as e:
            logger.error(f"Error querying {url}: {e}")
        return None

    def _parse_device_info(self, xml_text):
        """Parse ECP device-info XML into a dict."""
        info = {}
        try:
            root = ET.fromstring(xml_text)
            for child in root:
                info[child.tag] = child.text
        except ET.ParseError as e:
            logger.error(f"XML parse error: {e}")
        return info

    def _parse_apps(self, xml_text):
        """Parse ECP apps XML into list of app names."""
        apps = []
        try:
            root = ET.fromstring(xml_text)
            for app in root.findall('app'):
                apps.append(app.text)
        except ET.ParseError as e:
            logger.error(f"XML parse error: {e}")
        return apps

    def scan(self, ip):
        """
        Full ECP scan of a single IP.
        Returns dict with found info, or None if not a Roku.
        """
        logger.info(f"Scanning {ip}:8060 for Roku ECP...")

        # Check device-info first to confirm it's a Roku
        device_xml = self._query_ecp(ip, "/query/device-info")
        if not device_xml:
            logger.info(f"{ip}: No ECP response — not a Roku or ECP disabled")
            return None

        # Must contain roku-specific tags to count
        if "roku" not in device_xml.lower() and "serial-number" not in device_xml.lower():
            logger.info(f"{ip}: ECP responded but doesn't look like a Roku")
            return None

        info = self._parse_device_info(device_xml)

        result = {
            "ip":            ip,
            "model":         info.get("model-name",       "unknown"),
            "model_number":  info.get("model-number",     "unknown"),
            "serial":        info.get("serial-number",    "unknown"),
            "software":      info.get("software-version", "unknown"),
            "friendly_name": info.get("friendly-device-name", "unknown"),
            "udn":           info.get("udn",              "unknown"),
            "ecp_enabled":   True,
            "apps":          [],
        }

        logger.info(
            f"Roku found at {ip}\n"
            f"  Model:   {result['model']} ({result['model_number']})\n"
            f"  Name:    {result['friendly_name']}\n"
            f"  Serial:  {result['serial']}\n"
            f"  SW:      {result['software']}"
        )

        # Query installed apps
        apps_xml = self._query_ecp(ip, "/query/apps")
        if apps_xml:
            result["apps"] = self._parse_apps(apps_xml)
            logger.info(f"  Apps ({len(result['apps'])}): {', '.join(result['apps'][:5])}{'...' if len(result['apps']) > 5 else ''}")

        # Check active app
        active_xml = self._query_ecp(ip, "/query/active-app")
        if active_xml:
            try:
                root = ET.fromstring(active_xml)
                active = root.find('.//app')
                if active is not None:
                    result["active_app"] = active.text
                    logger.info(f"  Active app: {active.text}")
            except ET.ParseError:
                pass

        return result

    def execute(self, ip, port, row, status_key):
        """Bjorn action entry point."""
        try:
            result = self.scan(ip)
            if result:
                msg = (
                    f"Roku ECP found at {ip}\n"
                    f"Name:   {result['friendly_name']}\n"
                    f"Model:  {result['model']}\n"
                    f"Serial: {result['serial']}\n"
                    f"SW:     {result['software']}\n"
                    f"Apps:   {len(result['apps'])} installed"
                )
                send_ntfy(msg)
                return 'success'
            return 'failed'
        except Exception as e:
            logger.error(f"RokuECPScanner error on {ip}: {e}")
            return 'failed'