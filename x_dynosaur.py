import os,time,struct
from typing import Optional

_DYN_C = [0x9610b96b, 0xa2059a1c, 0xbf7d9295, 0x9cfd98d8]
_DYN_KA = [0x0cf899e0, 0xaeb64559, 0x5949af24, 0x8092054d, 0x0c95d927, 0x0b086719, 0xad111c64, 0xde807cca]
_DYN_NA = [0x1e8480, 0x2dc6c0, 0x3d0900]
_DYN_KB = [0xf0f5e403, 0xd13e697a, 0x412c053c, 0xa15a8711, 0x3efd4bc3, 0x20e0ca81, 0x4973a693, 0x042109db]
_DYN_NB = [0x78784664, 0xae90355d, 0xc84f968f]
_DYN_ST = [
    _DYN_C + _DYN_KA + [1000000]    + _DYN_NA,
    _DYN_C + _DYN_KA + [1000001]    + _DYN_NA,
    _DYN_C + _DYN_KB + [0xe308d2b4] + _DYN_NB,
    _DYN_C + _DYN_KB + [0xe308d2b5] + _DYN_NB,
    _DYN_C + _DYN_KB + [0xe308d2b6] + _DYN_NB,
    _DYN_C + _DYN_KB + [0xe308d2b7] + _DYN_NB,
]

DYN_ALPHABET = "Dkdpgh4ZKsQB80/Mfvw36XI1R25-WUAlEi7NLboqYTOPuzmFjJnryx9HVGcaStCe"

def _dyn_rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

def _dyn_qr(s: list, a: int, b: int, c: int, d: int) -> None:
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = _dyn_rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = _dyn_rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = _dyn_rotl(s[d] ^ s[a],  8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = _dyn_rotl(s[b] ^ s[c],  7)

def _dyn_chacha8_block(st: list) -> list:
    x = list(st)
    for _ in range(4):
        _dyn_qr(x, 0, 4,  8, 12); _dyn_qr(x, 1, 5,  9, 13)
        _dyn_qr(x, 2, 6, 10, 14); _dyn_qr(x, 3, 7, 11, 15)
        _dyn_qr(x, 0, 5, 10, 15); _dyn_qr(x, 1, 6, 11, 12)
        _dyn_qr(x, 2, 7,  8, 13); _dyn_qr(x, 3, 4,  9, 14)
    return [(x[i] + st[i]) & 0xFFFFFFFF for i in range(16)]

def _dyn_make_keystream() -> bytes:
    out = bytearray()
    for st in _DYN_ST:
        for word in _dyn_chacha8_block(st):
            out += struct.pack("<I", word)
    return bytes(out)

_DYN_KS = _dyn_make_keystream()

def _dyn_b64enc(data: bytes) -> str:
    out = []
    for i in range(0, len(data), 3):
        ch = data[i:i+3]
        n  = len(ch)
        b  = int.from_bytes(ch + b"\x00" * (3 - n), "big")
        cs = [(b >> (18 - 6 * j)) & 0x3F for j in range(n + 1)]
        if n == 1:
            cs[-1] |= 0x07
        elif n == 2:
            cs[-1] |= 0x02 
        out.append("".join(DYN_ALPHABET[c] for c in cs))
        out.append("=" * (3 - n))
    return "".join(out)

def dyn_url_hash(data) -> bytes:
    if isinstance(data, str):
        data = data.encode("utf-8")
    out = bytearray()
    for pos, c in enumerate(data):
        a = c ^ ((0x67 + pos) & 0xFF)
        a = (a + ((pos & 2) + 1)) & 0xFFFFFFFF
        a = ((a << 2) | 1) & 0xFF
        a = a ^ 0xBB
        a = a | 1
        out.append(a & 0xFF)
    out.append(0x00)
    out.append(len(data) & 0xFF)
    return bytes(out)

def _dyn_fnv1a(data: bytes) -> int:
    h = 2166136261
    for b in data:
        h = ((h ^ b) * 16777619) & 0xFFFFFFFF
    return h

_DYN_CALL_COUNTER = 0

def get_X_Dynosaur(
    query_string: str,
    user_agent: str = "Mozilla/5.0",
    body: str = "",
    timestamp: Optional[int] = None,
    device_seed: Optional[int] = None,
) -> str:
    global _DYN_CALL_COUNTER

    if timestamp is None:
        timestamp = int(time.time())
    ts_ms = (timestamp * 1000) & 0xFFFFFFFF

    q_bytes  = query_string.encode("utf-8") if isinstance(query_string, str) else query_string
    ua_bytes = user_agent.encode("utf-8")   if isinstance(user_agent,   str) else user_agent
    b_bytes  = body.encode("utf-8")         if isinstance(body,         str) else body

    url_fnv  = _dyn_fnv1a(q_bytes)
    ua_fnv   = _dyn_fnv1a(ua_bytes)
    body_fnv = _dyn_fnv1a(b_bytes) if b_bytes else 0

    nonce = struct.unpack("<I", os.urandom(4))[0]

    if device_seed is None:
        device_seed = struct.unpack("<I", os.urandom(4))[0]
    dev_block = bytearray()
    h = device_seed
    for _ in range(8):
        h = _dyn_fnv1a(struct.pack("<I", h))
        dev_block += struct.pack("<I", h)

    uh_q  = dyn_url_hash(q_bytes)[:14]
    uh_ua = dyn_url_hash(ua_bytes[:12])[:14]
    uh_q  = uh_q.ljust(14, b"\x00")[:14]
    uh_ua = uh_ua.ljust(14, b"\x00")[:14]

    _DYN_CALL_COUNTER = (_DYN_CALL_COUNTER + 1) & 0xFFFFFFFF

    cha_seed = (nonce ^ ts_ms ^ url_fnv ^ ua_fnv) & 0xFFFFFFFF
    cha_key  = bytearray()
    h = cha_seed
    for _ in range(8):
        h = _dyn_fnv1a(struct.pack("<I", h))
        cha_key += struct.pack("<I", h)
    cha_key = bytes(cha_key)

    cha_state = list(_DYN_C)
    cha_state += list(struct.unpack("<8I", cha_key))
    cha_state += [_DYN_CALL_COUNTER & 0xFFFFFFFF]
    cha_state += [nonce & 0xFFFFFFFF, ts_ms & 0xFFFFFFFF, body_fnv & 0xFFFFFFFF]
    cha_stream = bytearray()
    for ctr_off in range(4):
        st = list(cha_state)
        st[12] = (st[12] + ctr_off) & 0xFFFFFFFF
        for w in _dyn_chacha8_block(st):
            cha_stream += struct.pack("<I", w)
    tail = bytes(cha_stream[:206])

    p = bytearray(292)
    p[0]    = 0x4A
    p[1]    = 0x00
    struct.pack_into("<I", p,  2,  ts_ms)
    struct.pack_into("<I", p,  6,  nonce)
    struct.pack_into("<I", p, 10,  url_fnv)
    struct.pack_into("<I", p, 14,  ua_fnv)
    struct.pack_into("<I", p, 18,  body_fnv)
    p[22:36] = uh_q
    p[36:50] = uh_ua
    p[50:82] = dev_block
    struct.pack_into("<I", p, 82,  _DYN_CALL_COUNTER)
    p[86:292] = tail

    ct = bytes(p[i] ^ _DYN_KS[i] for i in range(len(p)))
    return _dyn_b64enc(ct).rstrip("=")

if __name__ == '__main__':
    query_params = "aid=1988&app_name=tiktok_web"
    request_body = ""
    browser_user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    token_dyn = get_X_Dynosaur(query_params, browser_user_agent, request_body)
    print(f"X-Dynosaur: {token_dyn}")
