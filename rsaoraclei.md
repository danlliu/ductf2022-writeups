
# oracle for block cipher enthusiasts
DownUnder CTF 2022; Crypto (Easy)

Writeup by danlliu from WolvSec (solved)

## General Approach

We are given a program that encrypts a 336-bit secret with 384-bit RSA. We have the ability to query the oracle with a "ciphertext" and determine if the decrypted ciphertext falls within a set of specified intervals. The program returns the most recent interval that the decrypted ciphertext falls in.

## Solution

The challenge code is shown below:

```python
#!/usr/bin/env python3

import signal, time
from os import urandom, path
from Crypto.Util.number import getPrime, bytes_to_long


FLAG = open(path.join(path.dirname(__file__), 'flag.txt'), 'r').read().strip()

N_BITS = 384
TIMEOUT = 20 * 60
MAX_INTERVALS = 384
MAX_QUERIES = 384


def main():
    p, q = getPrime(N_BITS//2), getPrime(N_BITS//2)
    N = p * q
    e = 0x10001
    d = pow(e, -1, (p - 1) * (q - 1))

    secret = bytes_to_long(urandom(N_BITS//9))
    c = pow(secret, e, N)

    print(N)
    print(c)

    intervals = []
    queries_used = 0

    while True:
        print('1. Add interval\n2. Request oracle\n3. Get flag')
        choice = int(input('> '))

        if choice == 1:
            if len(intervals) >= MAX_INTERVALS:
                print('No more intervals allowed!')
                continue

            lower = int(input(f'Lower bound: '))
            upper = int(input(f'Upper bound: '))
            intervals.insert(0, (lower, upper))

        elif choice == 2:
            queries = input('queries: ')
            queries = [int(c.strip()) for c in queries.split(',')]
            queries_used += len(queries)
            if queries_used > MAX_QUERIES:
                print('No more queries allowed!')
                continue

            results = []
            for c in queries:
                m = pow(c, d, N)
                for i, (lower, upper) in enumerate(intervals):
                    in_interval = lower < m < upper
                    if in_interval:
                        results.append(i)
                        break
                else:
                    results.append(-1)

            print(','.join(map(str, results)), flush=True)

            time.sleep(MAX_INTERVALS * (MAX_QUERIES // N_BITS - 1))
        elif choice == 3:
            secret_guess = int(input('Enter secret: '))
            if secret == secret_guess:
                print(FLAG)
            else:
                print('Incorrect secret :(')
            exit()

        else:
            print('Invalid choice')


if __name__ == '__main__':
    signal.alarm(TIMEOUT)
    main()
```

In this case, we are allowed up to 384 intervals, and up to 384 queries. We are provided with the value of `c`. From here, we realize that if we give the oracle `c` as the query, it will decrypt back to the secret. Thus, we can perform binary search on the value of the secret!

The solve script is shown below:

```python
import sys

from pwn import *

conn = remote('2022.ductf.dev',30008)
# conn = process('./rsa-interval-oracle-i.py')

N = 0
c = 0

current_intervals = []

def read_n_c(conn):
    global N, c
    N = int(conn.recvline())
    c = int(conn.recvline())
    print('N =', N)
    print('C =', c)

def read_header(conn):
    conn.recvline()
    conn.recvline()
    conn.recvline()

def setup_range(conn, start, end):
    current_intervals.append((start, end))
    read_header(conn)
    conn.sendline(b'1')
    conn.recv()
    conn.sendline(str(start).encode())
    conn.recv()
    conn.sendline(str(end).encode())

def make_query(conn):
    global c
    read_header(conn)
    conn.recv()
    conn.sendline(b'2')
    conn.recv()
    conn.sendline(str(c).encode())
    res = conn.recvline()
    return res

read_n_c(conn)

def guess_secret(conn, secret):
    read_header(conn)
    conn.recv()
    conn.sendline(b'3')
    conn.recv()
    conn.sendline(str(secret).encode())
    return conn.recvline()

def binary_search(conn, start, end):
    global s
    setup_range(conn, start, end)
    while start < end - 1:
        left = (start - 1, (start + end) // 2)
        setup_range(conn, *left)
        qr = make_query(conn)
        if qr == b'0\n':
            # in interval
            end = (start + end) // 2
        else:
            # in right
            start = (start + end) // 2
    return start

s = binary_search(conn, 0, 2 ** 338)
print('g', s)
print(guess_secret(conn, s))


```

Here, we have a relatively standard binary search algorithm; the trickiest part is to ensure that the `recv` and `recvline` calls are set up properly. From here, we can let it run to get the flag.

Solution: `DUCTF{d1d_y0u_us3_b1n4ry_s34rch?}`

Indeed we did!
