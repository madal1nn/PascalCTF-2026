#!/usr/bin/env python3
import os
from pwn import *
import logging

logging.disable()

HOST = os.environ.get("HOST", "curve.ctf.pascalctf.it")
PORT = int(os.environ.get("PORT", 5004))

p = 1844669347765474229
n = 1844669347765474230
Gx, Gy = 27, 728430165157041631
MODULI = [2, 9, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]

def add(P, Q):
    if P is None: return Q
    if Q is None: return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2:
        if (y1 + y2) % p == 0: return None
        s = 3 * x1 * x1 * pow(2 * y1, -1, p) % p
    else:
        s = (y2 - y1) * pow(x2 - x1, -1, p) % p
    x3 = (s * s - x1 - x2) % p
    y3 = (s * (x1 - x3) - y1) % p
    return (x3, y3)

def mul(k, P):
    R = None
    while k:
        if k & 1: R = add(R, P)
        P = add(P, P)
        k >>= 1
    return R

def crt(rems, mods):
    M = 1
    for m in mods: M *= m
    x = 0
    for r, m in zip(rems, mods):
        Mi = M // m
        x += r * Mi * pow(Mi, -1, m)
    return x % M

def oracle_mul(io, k, point_name):
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"k: ", str(k).encode())
    io.sendlineafter(b"P (G/Q/x,y): ", point_name.encode())
    
    line = io.recvline().decode()
    if "infinity" in line.lower():
        return None
    coords = line.split("(")[1].split(")")[0]
    x, y = coords.split(", ")
    return (int(x), int(y))

def main():
    io = remote(HOST, PORT)
    
    io.recvuntil(b"Q = (")
    parts = io.recvuntil(b")").decode().rstrip(")").split(", ")
    Qx, Qy = int(parts[0]), int(parts[1])
    Q = (Qx, Qy)
    G = (Gx, Gy)
    
    rems, mods = [], []
    
    for q in MODULI:
        cof = n // q        
        Gq = oracle_mul(io, cof, "G")
        Qq = oracle_mul(io, cof, "Q")        
        if Gq is None:
            continue
        
        for k in range(q):
            if mul(k, Gq) == Qq:
                rems.append(k)
                mods.append(q)
                break
    
    secret = crt(rems, mods)
    
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"secret (hex): ", hex(secret).encode())
    
    response = io.recvuntil(b"}").decode()
    flag = "pascalCTF{" + response.split("pascalCTF{")[1]
    print(flag)
    
    io.close()

if __name__ == "__main__":
    main()
