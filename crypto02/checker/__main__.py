#!/usr/bin/env python3

import os
import numpy as np
from pwn import *
import logging
logging.disable()

HOST = os.environ.get("HOST", "cramer.ctf.pascalctf.it")
PORT = int(os.environ.get("PORT", 5002))

r = remote(HOST, PORT)
lines = r.recvuntil(b'\n\n')
lines = lines.decode().strip().split('\n')

cs = []
ks = []

for line in lines:
   a = line.split(' = ')
   cs.append(int(a[1]))
   
   coeffs = a[0].split(' + ')
   kss = []
   
   for coeff in coeffs:
      kss.append(int(coeff.split('*')[0]))
   ks.append(kss)

x = np.linalg.solve(ks, cs)
print('pascalCTF{' + ''.join([chr(int(round(i))) for i in x]) + '}')