#!/usr/bin/env python3

import os
import requests
from pwn import *
import logging
logging.disable()

# Per le challenge web
URL = os.environ.get("URL", "http://jshit.ctf.pascalctf.it")
if URL.endswith("/"):
   URL = URL[:-1]

def checker():
   r = requests.get(URL)
   if r.status_code != 200:
      return "Connection error"
   if len(r.text) != 31364:
      return "Length error"
   return "pascalCTF{1_h4t3_j4v4scr1pt_s0o0o0o0_much}"


print(checker())
