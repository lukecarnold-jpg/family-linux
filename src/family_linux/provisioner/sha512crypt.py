"""SHA-512 crypt ($6$), as used by /etc/shadow on Debian.

Python 3.13 removed the crypt module, so the preseed generator needs its own implementation. It follows
Drepper's SHA-crypt specification, and tests check it against glibc's crypt() where available.
"""

from __future__ import annotations

import hashlib

_ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_ROUNDS = 5000
# Byte order used by the specification when encoding the 64-byte digest.
_TRIPLES = [
    (0, 21, 42), (22, 43, 1), (44, 2, 23), (3, 24, 45), (25, 46, 4), (47, 5, 26), (6, 27, 48),
    (28, 49, 7), (50, 8, 29), (9, 30, 51), (31, 52, 10), (53, 11, 32), (12, 33, 54), (34, 55, 13),
    (56, 14, 35), (15, 36, 57), (37, 58, 16), (59, 17, 38), (18, 39, 60), (40, 61, 19), (62, 20, 41),
]


def _encode(value: int, chars: int) -> str:
    out = ""
    for _ in range(chars):
        out += _ITOA64[value & 0x3F]
        value >>= 6
    return out


def sha512_crypt(password: str, salt: str) -> str:
    """Returns the full "$6$salt$hash" string for a password and salt (at most 16 characters)."""
    pw = password.encode("utf-8")
    slt = salt.encode("utf-8")[:16]
    plen = len(pw)

    digest_b = hashlib.sha512(pw + slt + pw).digest()
    a = hashlib.sha512(pw + slt)
    count = plen
    while count > 64:
        a.update(digest_b)
        count -= 64
    a.update(digest_b[:count])
    count = plen
    while count > 0:
        a.update(digest_b if count & 1 else pw)
        count >>= 1
    digest_a = a.digest()

    p_bytes = hashlib.sha512(pw * plen).digest()
    p_seq = (p_bytes * (plen // 64 + 1))[:plen]

    s_bytes = hashlib.sha512(slt * (16 + digest_a[0])).digest()
    s_seq = (s_bytes * (len(slt) // 64 + 1))[: len(slt)]

    c = digest_a
    for i in range(_ROUNDS):
        h = hashlib.sha512()
        h.update(p_seq if i & 1 else c)
        if i % 3:
            h.update(s_seq)
        if i % 7:
            h.update(p_seq)
        h.update(c if i & 1 else p_seq)
        c = h.digest()

    encoded = "".join(_encode((c[x] << 16) | (c[y] << 8) | c[z], 4) for x, y, z in _TRIPLES)
    encoded += _encode(c[63], 2)
    return f"$6${salt[:16]}${encoded}"
