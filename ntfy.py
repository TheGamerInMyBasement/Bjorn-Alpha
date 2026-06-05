# utils/ntfy.py
import requests
import json
import logging

logger = logging.getLogger("discord_webhook")

# Put your webhook URL here ONCE
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1511752087762108657/sGpxuhwVaiBXDdUKKQxS07RVp2Lwjw9ACf2TvTZ5U3MXH-xI2oJ0FOECRKVmmAtcWrQQ"

def send_ntfy(message: str):
    """
    Replacement for ntfy — sends notifications to a Discord webhook.
    """
    if not DISCORD_WEBHOOK_URL:
        logger.error("Discord webhook URL is not set.")
        return False

    payload = {
        "content": message
    }

    headers = {
        "Content-Type": "application/json"
    }

    try:
        r = requests.post(DISCORD_WEBHOOK_URL, data=json.dumps(payload), headers=headers, timeout=5)

        # Discord returns 204 No Content on success
        if r.status_code in (200, 204):
            return True

        logger.error(f"Discord webhook returned status {r.status_code}: {r.text}")
        return False

    except Exception as e:
        logger.error(f"Error sending Discord webhook: {e}")
        return False
