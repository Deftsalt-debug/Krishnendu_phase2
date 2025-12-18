# Attention is all you need
Provided is a CUDA file under an ELF executable

## Flag
```
nite{0ops_i_ov3rf1tt3d_ag4in}
```

## Solution 
The binary contains encrypted neural-network weights and runs the check on the GPU. Instead of trying to run/step through GPU code, we extract the GPU “fatbin” payload to recover the XOR key used for encryption, extract the encrypted weights from the main ELF, decrypt them, reimplement the model’s scoring on the CPU, pick the best character at each position which reconstructs the flag.

```py
#!/usr/bin/env python3

import sys
import struct
import re
from array import array

# ---------------------------
# Minimal ELF64 little-endian parsing
# ---------------------------

ELF_HDR_FMT = "<16sHHIQQQIHHHHHH"  # ELF64 header (little-endian)
SHDR_FMT    = "<IIQQQQIIQQ"        # ELF64 section header
SYMTAB_FMT  = "<IBBHQQ"            # ELF64 symbol entry (24 bytes)

def read_elf_header(buf: bytes) -> dict:
    e_ident, e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, \
    e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(ELF_HDR_FMT, buf, 0)

    if e_ident[:4] != b"\x7fELF":
        raise ValueError("Not an ELF file (magic mismatch).")
    if e_ident[4] != 2:
        raise ValueError("Not ELF64.")
    if e_ident[5] != 1:
        raise ValueError("Not little-endian ELF.")

    return {
        "e_shoff": e_shoff,
        "e_shentsize": e_shentsize,
        "e_shnum": e_shnum,
        "e_shstrndx": e_shstrndx,
    }

def parse_section_headers(buf: bytes, hdr: dict) -> list:
    shoff = hdr["e_shoff"]
    entsz = hdr["e_shentsize"]
    shnum = hdr["e_shnum"]

    shdrs = []
    for i in range(shnum):
        off = shoff + i * entsz
        sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = \
            struct.unpack_from(SHDR_FMT, buf, off)
        shdrs.append({
            "sh_name": sh_name,
            "sh_type": sh_type,
            "sh_flags": sh_flags,
            "sh_addr": sh_addr,
            "sh_offset": sh_offset,
            "sh_size": sh_size,
            "sh_link": sh_link,
            "sh_info": sh_info,
            "sh_addralign": sh_addralign,
            "sh_entsize": sh_entsize,
            "name": "",
        })

    # Resolve section names via section-header string table
    shstr = shdrs[hdr["e_shstrndx"]]
    shstr_data = buf[shstr["sh_offset"]: shstr["sh_offset"] + shstr["sh_size"]]

    for s in shdrs:
        n = s["sh_name"]
        end = shstr_data.find(b"\x00", n)
        s["name"] = shstr_data[n:end].decode("ascii", errors="replace") if end != -1 else ""
    return shdrs

def get_section_by_name(shdrs: list, name: str):
    for idx, s in enumerate(shdrs):
        if s["name"] == name:
            return idx, s
    return None, None

def parse_symbols_from_section(buf: bytes, shdrs: list, sym_section_name: str) -> dict:
    sym_idx, sym_sec = get_section_by_name(shdrs, sym_section_name)
    if sym_sec is None:
        return {}

    # linked string table holding symbol names
    str_sec = shdrs[sym_sec["sh_link"]]
    str_data = buf[str_sec["sh_offset"]: str_sec["sh_offset"] + str_sec["sh_size"]]

    sym_data = buf[sym_sec["sh_offset"]: sym_sec["sh_offset"] + sym_sec["sh_size"]]
    entsz = sym_sec["sh_entsize"] or 24

    syms = {}
    for off in range(0, len(sym_data), entsz):
        if off + entsz > len(sym_data):
            break
        st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from(SYMTAB_FMT, sym_data, off)
        if st_name == 0:
            continue
        end = str_data.find(b"\x00", st_name)
        if end == -1:
            continue
        name = str_data[st_name:end].decode("utf-8", errors="replace")
        syms[name] = {
            "st_shndx": st_shndx,
            "st_value": st_value,
            "st_size": st_size,
            "st_info": st_info,
        }
    return syms

def parse_symtab(buf: bytes, shdrs: list) -> dict:
    # Prefer .symtab, fall back to .dynsym (some binaries are stripped but keep dyn symbols)
    syms = parse_symbols_from_section(buf, shdrs, ".symtab")
    if syms:
        return syms
    syms = parse_symbols_from_section(buf, shdrs, ".dynsym")
    if syms:
        return syms
    raise ValueError("No .symtab or .dynsym found (symbols stripped).")

def read_symbol_bytes(buf: bytes, shdrs: list, sym: dict) -> bytes:
    sec = shdrs[sym["st_shndx"]]
    delta = sym["st_value"] - sec["sh_addr"]
    file_off = sec["sh_offset"] + delta
    return buf[file_off: file_off + sym["st_size"]]

# ---------------------------
# Find XOR key inside GPU fatbin payload
# ---------------------------

def scan_for_embedded_elfs(blob: bytes) -> list:
    idxs = []
    start = 0
    while True:
        i = blob.find(b"\x7fELF", start)
        if i == -1:
            break
        idxs.append(i)
        start = i + 1

    parts = []
    for j, i in enumerate(idxs):
        end = idxs[j + 1] if j + 1 < len(idxs) else len(blob)
        parts.append(blob[i:end])
    return parts

def extract_xor_key_from_cubin(cubin: bytes):
    """
    Challenge stores XOR_KEY as 16 bytes in .nv.constant3 of an embedded GPU ELF.
    """
    try:
        hdr = read_elf_header(cubin)
        shdrs = parse_section_headers(cubin, hdr)
        _, sec = get_section_by_name(shdrs, ".nv.constant3")
        if sec is None or sec["sh_size"] != 16:
            return None
        raw = cubin[sec["sh_offset"]: sec["sh_offset"] + 16]
        return struct.unpack("<4I", raw)
    except Exception:
        return None

# ---------------------------
# Decrypt weights (u32 XOR, then bitcast float32)
# ---------------------------

def decrypt_u32_to_f32(enc_bytes: bytes, key_u32: tuple) -> array:
    if len(enc_bytes) % 4 != 0:
        raise ValueError("Encrypted blob size not multiple of 4 bytes.")

    enc = array("I")
    enc.frombytes(enc_bytes)
    if sys.byteorder != "little":
        enc.byteswap()

    k0, k1, k2, k3 = key_u32
    for i in range(len(enc)):
        r = i & 3
        if r == 0:
            enc[i] ^= k0
        elif r == 1:
            enc[i] ^= k1
        elif r == 2:
            enc[i] ^= k2
        else:
            enc[i] ^= k3

    b = enc.tobytes()
    floats = array("f")
    floats.frombytes(b)
    if sys.byteorder != "little":
        floats.byteswap()

    return floats

def relu(x: float) -> float:
    return x if x > 0.0 else 0.0

# ---------------------------
# Solve
# ---------------------------

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} ./attention_is_all_you_need")
        sys.exit(1)

    path = sys.argv[1]
    buf = open(path, "rb").read()

    hdr = read_elf_header(buf)
    shdrs = parse_section_headers(buf, hdr)
    syms = parse_symtab(buf, shdrs)

    # Locate fatbin section
    _, fat_sec = get_section_by_name(shdrs, ".nv_fatbin")
    if fat_sec is None:
        raise RuntimeError("Could not find .nv_fatbin (no embedded CUDA fatbin?).")

    fatbin = buf[fat_sec["sh_offset"]: fat_sec["sh_offset"] + fat_sec["sh_size"]]
    cubins = scan_for_embedded_elfs(fatbin)

    key = None
    for c in cubins:
        key = extract_xor_key_from_cubin(c)
        if key is not None:
            break
    if key is None:
        raise RuntimeError("Could not locate XOR key in any embedded cubin (.nv.constant3 missing).")

    print("[+] XOR_KEY u32 words:", [hex(x) for x in key])

    # Extract charset used to map chars -> token IDs
    m = re.search(br"abcdefghijklmnopqrstuvwxyz0123456789\{\}_", buf)
    charset = m.group(0).decode("ascii") if m else "abcdefghijklmnopqrstuvwxyz0123456789{}_"
    vocab = len(charset)

    # Model dims (as designed in this challenge)
    seq = 29
    dim = 32
    hidden = 64

    want = [
        "EMBED_WEIGHT_ENC",
        "POS_EMBED_WEIGHT_ENC",
        "POS_FC1_WEIGHT_ENC",
        "POS_FC1_BIAS_ENC",
        "POS_FC2_WEIGHT_ENC",
        "POS_FC2_BIAS_ENC",
        "GLOBAL_FC1_WEIGHT_ENC",
        "GLOBAL_FC1_BIAS_ENC",
        "GLOBAL_FC2_WEIGHT_ENC",
    ]

    # Read + decrypt weights
    dec = {}
    for name in want:
        if name not in syms:
            raise RuntimeError(f"Missing symbol: {name} (binary may be stripped differently).")
        enc_blob = read_symbol_bytes(buf, shdrs, syms[name])
        dec[name] = decrypt_u32_to_f32(enc_blob, key)

    E   = dec["EMBED_WEIGHT_ENC"]         # [vocab*dim]
    P   = dec["POS_EMBED_WEIGHT_ENC"]     # [seq*dim]
    W1  = dec["POS_FC1_WEIGHT_ENC"]       # [seq*hidden*dim]
    B1  = dec["POS_FC1_BIAS_ENC"]         # [seq*hidden]
    W2  = dec["POS_FC2_WEIGHT_ENC"]       # [seq*hidden]
    B2  = dec["POS_FC2_BIAS_ENC"]         # [seq]
    GW1 = dec["GLOBAL_FC1_WEIGHT_ENC"]    # [hidden*dim]
    GB1 = dec["GLOBAL_FC1_BIAS_ENC"]      # [hidden]
    GW2 = dec["GLOBAL_FC2_WEIGHT_ENC"]    # [hidden]

    # Sanity checks for shape correctness
    assert len(E)   == vocab * dim
    assert len(P)   == seq * dim
    assert len(W1)  == seq * hidden * dim
    assert len(B1)  == seq * hidden
    assert len(W2)  == seq * hidden
    assert len(B2)  == seq
    assert len(GW1) == hidden * dim
    assert len(GB1) == hidden
    assert len(GW2) == hidden

    # Greedy per-position solve
    chosen = []
    x_vectors = []

    for p in range(seq):
        best_t = 0
        best_s = -1e30

        p_off = p * dim
        W1_base = p * hidden * dim
        B1_base = p * hidden
        W2_base = p * hidden
        b2 = B2[p]

        for t in range(vocab):
            t_off = t * dim
            x = [E[t_off + i] + P[p_off + i] for i in range(dim)]

            s = b2
            for h in range(hidden):
                w_off = W1_base + h * dim
                acc = B1[B1_base + h]
                for i in range(dim):
                    acc += W1[w_off + i] * x[i]
                a = relu(acc)
                s += W2[W2_base + h] * a

            if s > best_s:
                best_s = s
                best_t = t

        chosen.append(best_t)

        t_off = best_t * dim
        x_vectors.append([E[t_off + i] + P[p_off + i] for i in range(dim)])

    candidate = "".join(charset[t] for t in chosen)

    # Compute full score (pos + global) for confidence
    mvec = [0.0] * dim
    for p in range(seq):
        for i in range(dim):
            mvec[i] += x_vectors[p][i]
    inv = 1.0 / seq
    for i in range(dim):
        mvec[i] *= inv

    global_score = 0.0
    for h in range(hidden):
        acc = GB1[h]
        w_off = h * dim
        for i in range(dim):
            acc += GW1[w_off + i] * mvec[i]
        a = relu(acc)
        global_score += GW2[h] * a

    pos_sum = 0.0
    for p in range(seq):
        t = chosen[p]
        p_off = p * dim
        t_off = t * dim
        x = [E[t_off + i] + P[p_off + i] for i in range(dim)]

        W1_base = p * hidden * dim
        B1_base = p * hidden
        W2_base = p * hidden

        s = B2[p]
        for h in range(hidden):
            w_off = W1_base + h * dim
            acc = B1[B1_base + h]
            for i in range(dim):
                acc += W1[w_off + i] * x[i]
            a = relu(acc)
            s += W2[W2_base + h] * a
        pos_sum += s

    total = pos_sum + global_score

    print("[+] Charset:", charset)
    print("[+] Candidate:", candidate)
    print("[+] Score: pos_sum=%.6f global=%.6f total=%.6f" % (pos_sum, global_score, total))


if __name__ == "__main__":
    main()
```

This script more or less just rips the binary into the py script and offests a pointer exactly to the portion in the binary that we need. Instead of debugging GPU kernels, we reproduce the exact process on the CPU by parsing the ELF to locate .nv_fatbin and weight symbols, extracting the XOR key from embedded GPU ELF(s), decrypting the weights (XOR + float bitcast), rebuilding the scoring function in Python, solving the input by maximizing the score per position.