#!/usr/bin/env python3

import os
from pwn import *
import logging
logging.disable()

HOST = os.environ.get("HOST", "penguin.ctf.pascalctf.it")
PORT = int(os.environ.get("PORT", 5003))

words = [
   "biocompatibility", "biodegradability", "characterization", "contraindication",
   "counterbalancing", "counterintuitive", "decentralization", "disproportionate",
   "electrochemistry", "electromagnetism", "environmentalist", "internationality",
   "internationalism", "institutionalize", "microlithography", "microphotography",
   "misappropriation", "mischaracterized", "miscommunication", "misunderstanding",
   "photolithography", "phonocardiograph", "psychophysiology", "rationalizations",
   "representational", "responsibilities", "transcontinental", "unconstitutional"
]

def main():
   r = remote(HOST, PORT)

   encr = []

   for i in range(7):
      for e in range(4):
         idx = i * 4 + e
         r.recvuntil(str(e+1).encode() + b': ')
         r.sendline(words[idx].encode())

      r.recvuntil(b'Encrypted words: ')
      arr = r.recvline().strip().decode().split(' ')
      assert len(arr) == 4
      encr.extend(arr)

   r.recvuntil(b'Ciphertext: ')
   ciphertext = r.recvline().strip().decode().split(' ')

   assert len(ciphertext) == 5

   for i in range(5):
      r.recvuntil(f'word {i+1}: '.encode())
      r.sendline(words[encr.index(ciphertext[i])].encode())
      assert b'Correct' in r.recvline()

   return r.recvline().decode().strip() # flag

if __name__ == "__main__":
   print(main())