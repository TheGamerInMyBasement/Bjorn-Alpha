import json
import requests

CONFIG_PATH = "/home/bjorn/Bjorn/shared_config.json"

try:
    with open(CONFIG_PATH, "r") as f:
        _config = json.load(f)
        _topic = _config.get("ntfy", {}).get("topic", "BjornDefaultTopic")
except Exception:
    _topic = "" #PUT THE TOPIC RIGHT HERE

_NTFY_URL = f"https://ntfy.sh/{_topic}"

def send_ntfy(message=None):
    if not message:
        return
    try:
        requests.post(_NTFY_URL, data=message.encode("utf-8"))
    except Exception:
        pass
