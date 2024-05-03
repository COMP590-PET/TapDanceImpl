import re
from pathlib import Path

CENSOR_BLOCKED_URLS: list[re.Pattern] = list(
    map(re.compile, [r"bing\.com", r"duckduckgo\.com", r"tls-v1-2\.badssl\.com"])
)
ISP_REFRACT_URLS: list[re.Pattern] = list(map(re.compile, [r"reddit\.com"]))
"""When visiting any of these links, refract to somewhere else"""

PROXIES: dict[str, str] = {
    "http": "http://127.0.0.1:8080",
    "https": "https://127.0.0.1:8080",
}

RESOURCES: Path = Path("resources")
MITMPROXY_CERT_UNIX: Path = RESOURCES / "mitmproxy-ca-cert.pem"
MITMPROXY_CERT_WIN: Path = RESOURCES / "mitmproxy-ca-cert.p12"

HTTPS_PORT: int = 443
HTTP_PORT: int = 80
BADSSL_TLS_1_2_PORT: int = 1012
