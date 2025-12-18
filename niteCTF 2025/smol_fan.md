# Smol fan
Provided is a .py script of a server which upon connection can sign messages using ECDSA but it doesn’t directly give us a normal ECDSA signature (r, s).

Instead, after signing, it prints these weird values:
	•	m = r * s
	•	a = (10 + r)^11 mod m
	•	b = (10 + s)^13 mod m

And it refuses to sign the message "gimme_flag" unless we already have the signature for it. Therefore our solve must entail recovering the signing secret key (or at least be able to sign "gimme_flag") as well as submit a valid (r, s) for "gimme_flag".

## Flag
```
nite{1'm_a_smol_f4n_of_LLL!}
```

## Solution


```py
#!/usr/bin/env sage -python
from sage.all import (
    EllipticCurve, GF, Integer,
    inverse_mod, identity_matrix, block_matrix, matrix,
    QQ, ZZ, vector
)
from pwn import remote
from math import gcd
import hashlib


# -----------------------------
# Challenge parameters
# -----------------------------
HOST = "smol.chalz.nitectf25.live"
PORT = 1337

FLAG_MESSAGE = b"gimme_flag"

# server: k < 2^BITS
BITS = 200
INITIAL_SIGNATURES = 10  # start small; increase if LLL fails


# secp256k1 parameters
P_FIELD = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424


def sha256_mod_n(msg: bytes) -> Integer:
    return Integer(int.from_bytes(hashlib.sha256(msg).digest(), "big") % N_ORDER)


# -----------------------------
# Protocol client
# -----------------------------
class FanServerClient:
    """
    Wraps the menu protocol:
      1) get public key
      2) sign message (returns m,a,b)
      3) submit signature (r,s) for gimme_flag
    """
    def __init__(self, host: str, port: int):
        self.io = remote(host, port)

    def close(self):
        try:
            self.io.close()
        except Exception:
            pass

    def get_public_key(self):
        self.io.sendlineafter(b"> ", b"1")
        self.io.recvuntil(b"Qx = ")
        qx = int(self.io.recvline().strip())
        self.io.recvuntil(b"Qy = ")
        qy = int(self.io.recvline().strip())
        return qx, qy

    def request_signature_leak(self, msg: bytes):
        """
        Ask server to "sign" msg (not gimme_flag). Server prints:
          m = r*s
          a = (10+r)^11 mod m
          b = (10+s)^13 mod m
        """
        self.io.sendlineafter(b"> ", b"2")
        self.io.sendlineafter(b"Enter message as hex:", msg.hex().encode())

        self.io.recvuntil(b"m = ")
        m_val = int(self.io.recvline().strip())
        self.io.recvuntil(b"a = ")
        a_val = int(self.io.recvline().strip())
        self.io.recvuntil(b"b = ")
        b_val = int(self.io.recvline().strip())
        return m_val, a_val, b_val

    def submit_flag_signature(self, r: int, s: int) -> bytes:
        self.io.sendlineafter(b"> ", b"3")
        self.io.sendlineafter(b"Enter r:", str(r).encode())
        self.io.sendlineafter(b"Enter s:", str(s).encode())
        # read whatever comes back
        return self.io.recvall(timeout=3) or b""


# -----------------------------
# Leak → recover ECDSA signature
# -----------------------------
def recover_rs_from_leak(m_val: int, a_val: int, b_val: int):
    """
    Given:
      m = r*s
      a = (10+r)^11 mod m
      b = (10+s)^13 mod m

    We use:
      (10+r)^11 ≡ 10^11 (mod r)  => r | (a - 10^11)
      (10+s)^13 ≡ 10^13 (mod s)  => s | (b - 10^13)

    So:
      r = gcd(m, a - 10^11)
      s = gcd(m, b - 10^13)
    """
    r = gcd(m_val, a_val - (10**11))
    s = gcd(m_val, b_val - (10**13))

    # Sometimes you get r, sometimes you get s first; ensure r*s == m when possible.
    if r * s != m_val:
        # Fall back: if r divides m, set the other as quotient
        if r != 0 and m_val % r == 0:
            s = m_val // r
        elif s != 0 and m_val % s == 0:
            r = m_val // s

    return int(r), int(s)


# -----------------------------
# Lattice attack (HNP) to recover d
# -----------------------------
def recover_private_key_from_bounded_nonces(pub_point, zrs_list, bits=BITS):
    """
    Each ECDSA signature satisfies:
      s = k^{-1} (z + r*d) mod n
    Rearranged:
      k ≡ (z + r*d) * s^{-1} mod n

    Server uses k < 2^bits, i.e. k is unusually small.
    This becomes a Hidden Number Problem; we solve with LLL.

    We build a lattice that encodes the equations and look for a short vector
    that yields candidate k's, then compute d and verify it by checking d*G == PubKey.
    """
    B = 2 ** bits
    m = len(zrs_list)

    # Two top rows, then a diagonal block -n*I
    row0 = [B, 0]
    row1 = [0, B / N_ORDER]

    for (z, r, s) in zrs_list:
        inv_s = inverse_mod(s, N_ORDER)
        row0.append((inv_s * z) % N_ORDER)
        row1.append((inv_s * r) % N_ORDER)

    row0 = matrix(QQ, 1, len(row0), row0)
    row1 = matrix(QQ, 1, len(row1), row1)

    diag = -N_ORDER * identity_matrix(QQ, m)
    zeros_m_by_2 = matrix(QQ, m, 2, [0] * (m * 2))

    M = block_matrix([
        [row0],
        [row1],
        [block_matrix([[zeros_m_by_2, diag]])]
    ])

    reduced = M.LLL()

    for rr in reduced.rows():
        rr = vector(ZZ, [round(x) for x in rr])

        # rr[2+i] behaves like a candidate "k_i" (up to sign) under this embedding
        for i in range(m):
            z, r, s = zrs_list[i]
            k_guess = rr[i + 2]

            if abs(k_guess) >= B:
                continue

            for k in (k_guess, -k_guess):
                try:
                    d = (inverse_mod(r, N_ORDER) * (k * s - z)) % N_ORDER
                except ZeroDivisionError:
                    continue

                if d * GENERATOR == pub_point:
                    return int(d)

    return None


# -----------------------------
# Sign locally once we have d
# -----------------------------
def sign_message_with_private_key(msg: bytes, d: int):
    """
    Standard ECDSA signing on secp256k1, using a fresh random nonce k.
    (This is local, unrelated to the server’s weak k.)
    """
    z = int.from_bytes(hashlib.sha256(msg).digest(), "big") % N_ORDER

    while True:
        k = Integer.random_element(1, N_ORDER)
        R = k * GENERATOR
        r = int(Integer(R[0]) % N_ORDER)
        if r == 0:
            continue

        s = int((inverse_mod(k, N_ORDER) * (z + r * d)) % N_ORDER)
        if s == 0:
            continue

        return r, s


# -----------------------------
# Main
# -----------------------------
if __name__ == "__main__":
    CURVE = EllipticCurve(GF(P_FIELD), [0, 7])
    GENERATOR = CURVE(Gx, Gy)
    assert GENERATOR.order() == N_ORDER

    sig_target = INITIAL_SIGNATURES

    while True:
        client = FanServerClient(HOST, PORT)
        try:
            qx, qy = client.get_public_key()
            pub_point = CURVE(qx, qy)

            # Collect signatures (z, r, s)
            zrs = []
            for i in range(sig_target):
                msg = f"msg_{i}".encode()
                m_val, a_val, b_val = client.request_signature_leak(msg)
                r, s = recover_rs_from_leak(m_val, a_val, b_val)
                z = sha256_mod_n(msg)
                zrs.append((Integer(z), Integer(r), Integer(s)))
                print(f"[+] got {i+1}/{sig_target}")

            d = recover_private_key_from_bounded_nonces(pub_point, zrs, bits=BITS)
            if d is None:
                print("[!] LLL failed; retrying with more signatures...")
                sig_target = min(sig_target + 2, 20)
                continue

            r_flag, s_flag = sign_message_with_private_key(FLAG_MESSAGE, d)
            resp = client.submit_flag_signature(r_flag, s_flag)
            print(resp.decode(errors="ignore"))
            break

        finally:
            client.close()
```


