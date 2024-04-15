from mitmproxy import http
import logging
import re

BLOCKED_URLS = []


# From https://dev.to/dandyvica/use-mitmproxy-as-a-personal-firewall-4m6h
class BlockResource:
    def __init__(self):
        for re_url in open("urls.txt"):
            BLOCKED_URLS.append(re.compile(re_url.strip()))
        logging.info(f"{len(BLOCKED_URLS)} urls read")

    def request(self, flow: http.HTTPFlow) -> None:
        if any(re.search(url, flow.request.url) for url in BLOCKED_URLS):
            logging.info(f"found match for {flow.request.url}")
            flow.response = http.Response.make(
                404, b"You have visited a blocked URL\n", {"Content-Type": "text/plain"}
            )


addons = [BlockResource()]
