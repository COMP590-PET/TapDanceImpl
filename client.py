# Usage: After running censor.py (following the usage instructions there), run python -m client

import requests
from pathlib import Path

PROXIES: dict[str, str] = {
    "http": "http://127.0.0.1:8080",
    "https": "https://127.0.0.1:8080",
}
MITMPROXY_CERT: Path = Path("resources") / "mitmproxy-ca-cert.pem"


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
