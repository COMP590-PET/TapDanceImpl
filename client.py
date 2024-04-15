import requests

response = requests.get("https://www.bing.com")
print(response.status_code)
response = requests.get("https://www.google.com")
print(response.status_code)
