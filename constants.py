import re
from pathlib import Path

CENSOR_BLOCKED_URLS: list[re.Pattern] = list(
    map(re.compile, [r"bing\.com", r"duckduckgo\.com"])
)
ISP_REFRACT_URLS: list[re.Pattern] = list(map(re.compile, [r"reddit\.com"]))
"""When visiting any of these links, refract to somewhere else"""

PROXIES: dict[str, str] = {
    "http": "http://127.0.0.1:8080",
    "https": "https://127.0.0.1:8080",
}
MITMPROXY_CERT: Path = Path("resources") / "mitmproxy-ca-cert.pem"

HTTPS_PORT: int = 443
HTTP_PORT: int = 80
