#!/usr/bin/env python3
from pwn import *

logging.disable()

ALPHABET = "abcdefghijklmnop"
NSTATE = 624
M = 397
A_CONST = 0x9908B0DF

LOW_BITS = 20

HOST = os.environ.get("HOST", "wordy.ctf.pascalctf.it")
PORT = int(os.environ.get("PORT", 5005))

def word_to_index(word: str) -> int:
    if len(word) != 5:
        raise ValueError("bad length")
    x = 0
    for ch in word:
        d = ALPHABET.find(ch)
        if d < 0:
            raise ValueError("bad letter")
        x = (x << 4) | d
    return x

def index_to_word(idx: int) -> str:
    if not (0 <= idx < (1 << 20)):
        raise ValueError("bad idx")
    digs = []
    for _ in range(5):
        digs.append(idx & 0xF)
        idx >>= 4
    digs.reverse()
    return "".join(ALPHABET[d] for d in digs)

def temper_int(x: int) -> int:
    y = x & 0xFFFFFFFF
    y ^= (y >> 11)
    y ^= ((y << 7) & 0x9D2C5680)
    y ^= ((y << 15) & 0xEFC60000)
    y ^= (y >> 18)
    return y & 0xFFFFFFFF

TEMP_ROWS_BITS = [[] for _ in range(32)]
for k in range(32):
    out = temper_int(1 << k)
    for t in range(32):
        if (out >> t) & 1:
            TEMP_ROWS_BITS[t].append(k)
TEMP_ROWS_BITS_LOW20 = [TEMP_ROWS_BITS[t] for t in range(LOW_BITS)]

A_BITS = [(A_CONST >> b) & 1 for b in range(32)]

class GF2Elim:
    def __init__(self, nvars: int):
        self.n = nvars
        self.pivots = {}

    def add_equation(self, mask: int, rhs: int):
        row = mask
        val = rhs & 1
        while row:
            p = row.bit_length() - 1
            piv = self.pivots.get(p)
            if piv is None:
                self.pivots[p] = (row, val)
                return
            row ^= piv[0]
            val ^= piv[1]
        if val != 0:
            raise RuntimeError("Inconsistent equations encountered")

    def predict(self, mask: int):
        row = mask
        val = 0
        while row:
            p = row.bit_length() - 1
            piv = self.pivots.get(p)
            if piv is None:
                return None
            row ^= piv[0]
            val ^= piv[1]
        return val

def initial_state_expr():
    state = []
    for i in range(NSTATE):
        word = []
        base = i * 32
        for b in range(32):
            word.append(1 << (base + b))
        state.append(word)
    return state

def twist_expr(state):
    N = NSTATE
    out = [[0] * 32 for _ in range(N)]
    for i in range(N):
        iM = (i + M) % N
        ip1 = (i + 1) % N

        for k in range(32):
            m = state[iM][k]
            if k <= 29:
                m ^= state[ip1][k + 1]
            elif k == 30:
                m ^= state[i][31]
            if A_BITS[k]:
                m ^= state[ip1][0]
            out[i][k] = m
    return out

def temper_expr_low20(word_expr):
    out = []
    for t in range(LOW_BITS):
        m = 0
        for k in TEMP_ROWS_BITS_LOW20[t]:
            m ^= word_expr[k]
        out.append(m)
    return out


def recover_round_word(conn: remote) -> int:
    conn.sendline(b"NEW")
    while True:
        line = conn.recvline()
        if line.startswith(b"ROUND STARTED"):
            break
        if line.startswith(b"ERR"):
            raise RuntimeError("Server refused NEW (maybe hit 1300 rounds limit)")
    
    secret = [None] * 5
    remaining = 5
    for ch in ALPHABET:
        conn.sendline(f"GUESS {ch * 5}".encode())
        patt = ""
        while True:
            line = conn.recvline()
            if line.startswith(b"FEEDBACK "):
                patt = line.split(b" ", 1)[1].strip().decode()
                break
            if line.startswith(b"ERR"):
                raise RuntimeError("GUESS got ERR")
        for i, c in enumerate(patt):
            if c == 'G' and secret[i] is None:
                secret[i] = ch
                remaining -= 1
        if remaining == 0:
            break
    if remaining != 0:
        raise RuntimeError("Failed to determine word in a round")
    w = "".join(secret)
    return word_to_index(w)

def main():
    conn = remote(HOST, PORT)
    conn.recvuntil(b'READY\n')

    nvars = NSTATE * 32
    elim = GF2Elim(nvars)

    cur_state = initial_state_expr()
    cur_idx = 0
    rounds_used = 0
    MAX_ROUNDS = 2000

    successes = 0
    REQUIRED = 5

    while successes < REQUIRED:
        while True:
            idx20 = recover_round_word(conn)
            rounds_used += 1
            low_masks = temper_expr_low20(cur_state[cur_idx])
            for t in range(LOW_BITS):
                bit = (idx20 >> t) & 1
                elim.add_equation(low_masks[t], bit)
            cur_idx += 1
            if cur_idx == NSTATE:
                cur_state = twist_expr(cur_state)
                cur_idx = 0

            next_masks = temper_expr_low20(cur_state[cur_idx])
            bits = []
            ok = True
            for t in range(LOW_BITS):
                b = elim.predict(next_masks[t])
                if b is None:
                    ok = False
                    break
                bits.append(b)
            if ok:
                pred = 0
                for t, b in enumerate(bits):
                    if b:
                        pred |= (1 << t)
                final_word = index_to_word(pred)
                conn.sendline(f"FINAL {final_word}".encode())
                resp = conn.recvline().decode().strip()
                parts = resp.split()
                if len(parts) < 2 or parts[0] != "OK":
                    raise RuntimeError(f"Unexpected FINAL response: {resp}")
                revealed_word = parts[1]
                idx20_revealed = word_to_index(revealed_word)
                successes += 1
                low_masks_revealed = temper_expr_low20(cur_state[cur_idx])
                for t in range(LOW_BITS):
                    bit = (idx20_revealed >> t) & 1
                    elim.add_equation(low_masks_revealed[t], bit)
                cur_idx += 1
                if cur_idx == NSTATE:
                    cur_state = twist_expr(cur_state)
                    cur_idx = 0
                if len(parts) >= 3 and '{' in parts[2]:
                    print(parts[2])
                    return
                break
            if rounds_used >= MAX_ROUNDS:
                raise RuntimeError("Too many rounds without prediction; aborting")

if __name__ == "__main__":
    main()
