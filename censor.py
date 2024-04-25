# Usage: mitmdump -s ./censor.py

from mitmproxy import http
import logging
import re
from constants import CENSOR_BLOCKED_URLS, ISP_REFRACT_URLS


# From https://dev.to/dandyvica/use-mitmproxy-as-a-personal-firewall-4m6h
class BlockResource:
    def __init__(self):
        logging.info(f"{len(CENSOR_BLOCKED_URLS)} censored URL's read")
        logging.info(f"{len(ISP_REFRACT_URLS)} refract URL's read")

    def request(self, flow: http.HTTPFlow) -> None:
        self.censor(flow)
        self.isp(flow)

    def censor(self, flow: http.HTTPFlow) -> None:
        if any(re.search(url, flow.request.url) for url in CENSOR_BLOCKED_URLS):
            logging.info(f"Censor found match for {flow.request.url}")
            flow.response = http.Response.make(
                404, b"You have visited a blocked URL\n", {"Content-Type": "text/plain"}
            )

    def isp(self, flow: http.HTTPFlow) -> None:
        if any(re.search(url, flow.request.url) for url in ISP_REFRACT_URLS):
            logging.info(f"Isp found match for {flow.request.url}")
            flow.request.host = "www.youtube.com"


addons = [BlockResource()]
