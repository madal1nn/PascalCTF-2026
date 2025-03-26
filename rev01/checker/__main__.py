#!/usr/bin/env python3

import os
from pwn import *
import logging
logging.disable()


HOST = os.environ.get("HOST", "auratester.ctf.pascalctf.it")
PORT = int(os.environ.get("PORT", 7001))

def main():
    p = remote(HOST, PORT)

    p.sendlineafter(b"> ", b"checker")
    p.sendlineafter(b"> ", b"1")
    p.sendlineafter(b"> ", b"yes")
    p.sendlineafter(b"> ", b"no")
    p.sendlineafter(b"> ", b"yes")
    p.sendlineafter(b"> ", b"no")
    p.sendlineafter(b"> ", b"3")

    p.recvuntil(b": ")
    phrase = p.recvline().strip().decode()
    step = 0
    real_phrase = ""
    still_number = False
    current_number = ""
    for c in phrase:
        if c.isdigit():
            current_number += c
            still_number = True
        else:
            if still_number:
                real_phrase += chr(int(current_number))
            
            still_number = False
            current_number = ""
            real_phrase += c

    p.sendlineafter(b"> ", real_phrase.encode())
    p.recvline()
    p.recvline()

    return p.recvline().strip().decode()

print(main())
