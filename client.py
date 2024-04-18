import requests

proxies = {
    "http": "http://127.0.0.1:8080",
}

response = requests.get("http://www.google.com", proxies=proxies)
print(f"Status code: {response.status_code}")
print(f"Text: {response.text}")
