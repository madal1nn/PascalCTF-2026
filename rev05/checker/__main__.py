#!/usr/bin/env python3

import os
from pwn import *
from pyshark import LiveCapture
import logging

logging.disable()

HOST = os.environ.get("HOST", "mysterious.ctf.pascalctf.it")
PORT = int(os.environ.get("PORT", 7005))

t = LiveCapture(interface="any", bpf_filter="icmp6")
r = remote(HOST, PORT)
t.sniff(packet_count=5, timeout=10)
for i in range(5):
    r.recvuntil(b'Your move (A1..C3, Q to quit): ')
    r.sendline(b'A1')

for packet in t:
    if hasattr(packet.icmpv6, 'Data'):
        data = bytes.fromhex(str(packet.icmpv6.Data).replace(':', '')).decode()
        if data.startswith("pascalCTF{") and data.endswith("}"):
            print(data)
            break