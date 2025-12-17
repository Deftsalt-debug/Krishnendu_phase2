# Stronk Rabin
Provided is two .py files

## Flag
```
nite{rabin_stronk?_no_r4bin_brok3n}
```

## Solution
Given in the server script, we see that it is a rabin cryptosystem style service which builds a secret modulus n = p * q * r * s where each prime is 3 mod 4. It then encrypts the flag as C = flag^2 * mod n. The script exposes two functions ENC (c) and DEC (c). When the server returns: ENC(m) = m^2 mod n, that means there exists some integer k such that:
m^2 - ENC (m) = k . n; So for each random message m, the value d = m^2 - ENC (m) is a multiple of n.
If we do this for multiple random m1, m2, and so on, then all the corresponding d's share the common factor n. So:
gcd(d1, d2,...) is appoximately n. In our script, derive_modulus() does precicely this function. Now DEC(1) returns some randomized value that is constructed from the square roots of 1 mod n. If we sample DEC(1) twice: a = DEC(1) and b = DEC(1). From which the difference a-b often ends up being divisible by some prime factors of n, but not all of them.
Then taking g = gcd(|a-b|, n) will yield a nontrivial factor 1 < g < n.

That’s what find_nontrivial_divisor() is doing in a loop until it gets a useful split.

Then split_into_primes() recursively repeats this, if a factor isn’t prime, split again until it has all four primes.

Now we know p,q,r,s and still have:
C = flag^2 * mod(pqrs)

So each prime gives 2 possible roots, and with 4 primes we get 2^4 = 16 possible square roots modulo n
Using CRT (Chinese Remainder Theorem), we combine one choice per prime into a full root mod n. That’s rabin_decrypt_candidates().

Amongst these 16 candidates, there's only one which fits the flag format, picking that, we get the answer.

```py
#!/usr/bin/env python3
import json, random
from math import gcd
from typing import List, Dict, Any
from Crypto.Util.number import long_to_bytes
from pwn import remote
from sympy import isprime
from sympy.ntheory.modular import crt

SERVER_HOST = "stronk.chals.nitectf25.live"
SERVER_PORT = 1337

def read_json_line(conn) -> Dict[str, Any]:
    while True:
        raw = conn.recvline(timeout=5)
        if not raw:
            raise EOFError("Connection closed")
        s = raw.decode(errors="replace").strip()
        if not s:
            continue
        try:
            return json.loads(s)
        except json.JSONDecodeError:
            continue

def call_oracle(conn, name: str, args: List[int]) -> int:
    conn.sendline(json.dumps({"func": name, "args": [int(x) for x in args]}).encode())
    return int(read_json_line(conn)["retn"])

def oracle_square(conn, msg: int) -> int:
    return call_oracle(conn, "ENC", [msg])

def oracle_dec(conn, ct: int) -> int:
    return call_oracle(conn, "DEC", [ct])

def derive_modulus(conn, samples: int = 8) -> int:
    acc = 0
    for _ in range(samples):
        m = random.getrandbits(1200)
        acc = gcd(acc, abs(m*m - oracle_square(conn, m))) if acc else abs(m*m - oracle_square(conn, m))
    for _ in range(3):
        t = random.getrandbits(400)
        if oracle_square(conn, t) != pow(t, 2, acc):
            raise ValueError("Modulus recovery sanity-check failed")
    return acc

def find_nontrivial_divisor(conn, composite: int) -> int:
    while True:
        a = oracle_dec(conn, 1)
        b = oracle_dec(conn, 1)
        d = gcd(abs(a - b), composite)
        if 1 < d < composite:
            return d

def split_into_primes(conn, n: int) -> List[int]:
    stack, primes = [n], []
    while stack:
        x = int(stack.pop())
        if isprime(x):
            primes.append(x)
        else:
            d = find_nontrivial_divisor(conn, x)
            stack.extend([d, x // d])
    return primes

def rabin_decrypt_candidates(cipher: int, primes: List[int]) -> List[int]:
    N = 1
    for p in primes:
        N *= int(p)
    roots = []
    for p in primes:
        p = int(p)
        r = pow(cipher % p, (p + 1) // 4, p)
        roots.append((r, (-r) % p))
    out = []
    for mask in range(1 << len(primes)):
        residues = [roots[i][(mask >> i) & 1] for i in range(len(primes))]
        x, _ = crt(primes, residues)
        out.append(int(x) % N)
    return out

def pick_flag_bytes(cands: List[int], modulus: int) -> bytes:
    for x in cands:
        b = long_to_bytes(x)
        if b"nite{" in b:
            return b
        b2 = long_to_bytes((modulus - x) % modulus)
        if b"nite{" in b2:
            return b2
    chosen = max(cands)
    if chosen <= modulus // 2:
        chosen = modulus - chosen
    return long_to_bytes(chosen)

def main() -> None:
    conn = remote(SERVER_HOST, SERVER_PORT, ssl=True)
    C = None
    while C is None:
        obj = read_json_line(conn)
        if isinstance(obj, dict) and "C" in obj:
            C = int(obj["C"])
    n = derive_modulus(conn)
    primes = sorted(split_into_primes(conn, n))
    candidates = rabin_decrypt_candidates(C, primes)
    flag_bytes = pick_flag_bytes(candidates, n)
    print(flag_bytes.decode(errors="ignore"))
    conn.close()

if __name__ == "__main__":
    main()
```