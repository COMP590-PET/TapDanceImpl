import re

CENSOR_BLOCKED_URLS: list[re.Pattern] = list(
    map(re.compile, [r"bing\.com", r"duckduckgo\.com"])
)
ISP_REFRACT_URLS: list[re.Pattern] = list(map(re.compile, [r"reddit\.com"]))
"""When visiting any of these links, refract to somewhere else"""
