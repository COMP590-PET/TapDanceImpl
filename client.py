# Usage: After running censor.py (following the usage instructions there), run python -m client

from pathlib import Path
import requests
from constants import PROXIES, MITMPROXY_CERT, RESOURCES
import os
import sslkeylog

sslkeylog.set_keylog(RESOURCES / "sslkeylog.txt")


def main() -> None:
    get_blocked()
    get_not_blocked()


def get_not_blocked() -> None:
    response = requests.get(
        "https://www.google.com", proxies=PROXIES, verify=str(MITMPROXY_CERT)
    )
    assert response.status_code == 200


def get_blocked() -> None:
    response = requests.get(
        "https://www.bing.com", proxies=PROXIES, verify=str(MITMPROXY_CERT)
    )
    assert response.status_code == 404


if __name__ == "__main__":
    main()
