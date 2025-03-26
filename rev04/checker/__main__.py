#!/usr/bin/env python3

import os
from pwn import *
import logging
logging.disable()

HOST = os.environ.get("HOST", "albo.ctf.pascalctf.it")
PORT = int(os.environ.get("PORT", 7004))

def check():
    a = ['Blaise', 'Pascal', '11/01/1937', 'M', 'Firenze']
    r = remote(HOST, PORT)
    
    r.recvuntil(b'\n\n')

    for i in a:
        r.sendlineafter(b': ', i.encode())
    
    r.recvuntil(b'flag: ')
    flag = r.recvline().strip().decode()
    r.close()

    print(flag)

if __name__ == "__main__":
    check()
