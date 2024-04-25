# Usage: After running censor.py (following the usage instructions there), run python -m client

import requests
from constants import PROXIES, MITMPROXY_CERT


def main() -> None:
    response = requests.get(
        "https://www.google.com", proxies=PROXIES, verify=str(MITMPROXY_CERT)
    )
    assert response.status_code == 200
    response = requests.get(
        "https://www.bing.com", proxies=PROXIES, verify=str(MITMPROXY_CERT)
    )
    assert response.status_code == 404


if __name__ == "__main__":
    main()
