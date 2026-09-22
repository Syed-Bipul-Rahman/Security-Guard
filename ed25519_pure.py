#!/usr/bin/env python3
"""
ed25519_pure.py - dependency-free Ed25519 sign/verify (public-domain reference impl).

Used so the Guard binary can verify signed update manifests with NO third-party
crypto dependency (keeps the single binary self-contained). The reference impl is
slow, but the agent verifies one small manifest occasionally, so speed is irrelevant.

verify() is what the deployed binary uses. sign()/publickey() are for the offline
release signer (keep the seed/secret key OUT of the binary and off user machines).
"""

from __future__ import annotations

import hashlib

b = 256
q = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493


def _H(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()


def _expmod(base, e, m):
    if e == 0:
        return 1
    t = _expmod(base, e // 2, m) ** 2 % m
    if e & 1:
        t = (t * base) % m
    return t


def _inv(x):
    return _expmod(x, q - 2, q)


d = -121665 * _inv(121666) % q
I = _expmod(2, (q - 1) // 4, q)


def _xrecover(y):
    xx = (y * y - 1) * _inv(d * y * y + 1)
    x = _expmod(xx, (q + 3) // 8, q)
    if (x * x - xx) % q != 0:
        x = (x * I) % q
    if x % 2 != 0:
        x = q - x
    return x


By = 4 * _inv(5) % q
Bx = _xrecover(By)
B = [Bx % q, By % q]


def _edwards(P, Q):
    x1, y1 = P
    x2, y2 = Q
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + d * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - d * x1 * x2 * y1 * y2)
    return [x3 % q, y3 % q]


def _scalarmult(P, e):
    if e == 0:
        return [0, 1]
    Q = _scalarmult(P, e // 2)
    Q = _edwards(Q, Q)
    if e & 1:
        Q = _edwards(Q, P)
    return Q


def _encodeint(y):
    bits = [(y >> i) & 1 for i in range(b)]
    return bytes(sum(bits[i * 8 + j] << j for j in range(8)) for i in range(b // 8))


def _encodepoint(P):
    x, y = P
    bits = [(y >> i) & 1 for i in range(b - 1)] + [x & 1]
    return bytes(sum(bits[i * 8 + j] << j for j in range(8)) for i in range(b // 8))


def _bit(h, i):
    return (h[i // 8] >> (i % 8)) & 1


def publickey(sk: bytes) -> bytes:
    """32-byte public key from a 32-byte secret seed."""
    h = _H(sk)
    a = 2 ** (b - 2) + sum(2 ** i * _bit(h, i) for i in range(3, b - 2))
    A = _scalarmult(B, a)
    return _encodepoint(A)


def _Hint(m):
    h = _H(m)
    return sum(2 ** i * _bit(h, i) for i in range(2 * b))


def sign(m: bytes, sk: bytes, pk: bytes) -> bytes:
    """64-byte signature over m. sk = 32-byte seed, pk = publickey(sk)."""
    h = _H(sk)
    a = 2 ** (b - 2) + sum(2 ** i * _bit(h, i) for i in range(3, b - 2))
    r = _Hint(bytes(h[i] for i in range(b // 8, b // 4)) + m)
    R = _scalarmult(B, r)
    S = (r + _Hint(_encodepoint(R) + pk + m) * a) % L
    return _encodepoint(R) + _encodeint(S)


def _isoncurve(P):
    x, y = P
    return (-x * x + y * y - 1 - d * x * x * y * y) % q == 0


def _decodeint(s):
    return sum(2 ** i * _bit(s, i) for i in range(0, b))


def _decodepoint(s):
    y = sum(2 ** i * _bit(s, i) for i in range(0, b - 1))
    x = _xrecover(y)
    if x & 1 != _bit(s, b - 1):
        x = q - x
    P = [x, y]
    if not _isoncurve(P):
        raise ValueError("point not on curve")
    return P


def verify(signature: bytes, m: bytes, pk: bytes) -> bool:
    """True iff signature is a valid Ed25519 signature of m under public key pk."""
    try:
        if len(signature) != b // 4 or len(pk) != b // 8:
            return False
        R = _decodepoint(signature[0:b // 8])
        A = _decodepoint(pk)
        S = _decodeint(signature[b // 8:b // 4])
        h = _Hint(_encodepoint(R) + pk + m)
        return _scalarmult(B, S) == _edwards(R, _scalarmult(A, h))
    except Exception:
        return False


if __name__ == "__main__":
    import os
    # self-test: generate a key, sign, verify, and reject tampering
    seed = os.urandom(32)
    pk = publickey(seed)
    msg = b'{"version":"1.1.0"}'
    sig = sign(msg, seed, pk)
    print("verify good sig :", verify(sig, msg, pk))
    print("reject tampered :", not verify(sig, msg + b"x", pk))
    print("reject wrong key:", not verify(sig, msg, publickey(os.urandom(32))))
    print("pubkey (hex)    :", pk.hex())
