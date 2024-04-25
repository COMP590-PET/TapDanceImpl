# Usage: After running censor.py (following the usage instructions there), run python -m client

import requests

PROXIES = {"http": "http://127.0.0.1:8080", "https": "https://127.0.0.1:8080"}


def main() -> None:
    response = requests.get("http://www.google.com", proxies=PROXIES)
    print(f"Status code: {response.status_code}")
    print(f"Text: {response.text}")


if __name__ == "__main__":
    main()
