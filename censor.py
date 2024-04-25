# Usage: mitmdump -s ./censor.py

from mitmproxy import http
import logging
import re

CENSOR_BLOCKED_URLS: list[re.Pattern] = list(map(re.compile, [r"bing\.com"]))
ISP_REFRACT_URLS: list[re.Pattern] = list(map(re.compile, [r"youtube\.com"]))
"""When visiting any of these links, refract to somewhere else"""


# From https://dev.to/dandyvica/use-mitmproxy-as-a-personal-firewall-4m6h
class BlockResource:
    def __init__(self):
        logging.info(f"{len(CENSOR_BLOCKED_URLS)} censored urls read")
        logging.info(f"{len(ISP_REFRACT_URLS)} refract urls read")

    def request(self, flow: http.HTTPFlow) -> None:
        # censor
        if any(re.search(url, flow.request.url) for url in CENSOR_BLOCKED_URLS):
            logging.info(f"censor found match for {flow.request.url}")
            flow.response = http.Response.make(
                404, b"You have visited a blocked URL\n", {"Content-Type": "text/plain"}
            )

        # isp
        if any(re.search(url, flow.request.url) for url in ISP_REFRACT_URLS):
            logging.info(f"isp found match for {flow.request.url}")
            flow.request.host = "www.reddit.com"


addons = [BlockResource()]
