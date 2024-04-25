from constants import CENSOR_BLOCKED_URLS, PROXIES, MITMPROXY_CERT
from subprocess import Popen
import requests


def censor(func):
    def censor_wrapper():
        censor_process: Popen = Popen(["mitmdump", "-s", "./censor.py"])
        func()
        censor_process.kill()

    return censor_wrapper


@censor
def test_censor():
    for pattern in CENSOR_BLOCKED_URLS:
        url: str = pattern.pattern
        url = url.replace("\\", "")
        url = "https://www." + url

        response = requests.get(url, proxies=PROXIES, verify=str(MITMPROXY_CERT))
        assert response.status_code == 404

@censor
def test_noncensored():
    response = requests.get("https://www.jessewei.dev", proxies=PROXIES, verify=str(MITMPROXY_CERT))
    assert response.status_code == 200
