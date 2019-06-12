from __future__ import absolute_import

from hashlib import sha256, sha512


def sha512_as_int(value):
    """
    Convert a SHA512 hash to an integer.
    """
    out = 0
    hashed = sha512(value).digest()
    for i in range(len(hashed)):
        out <<= 8
        out |= ord(hashed[i:i + 1])
    return out


def sha256_as_int(value):
    """
    Convert a SHA256 hash to an integer.
    """
    out = 0
    hashed = sha256(value).digest()
    for i in range(len(hashed)):
        out <<= 8
        out |= ord(hashed[i:i + 1])
    return out


def sha256_4_as_int(value):
    """
    Convert a SHA256 4 byte hash to an integer.
    """
    out = 0
    hashed = sha256(value).digest()[:4]
    for i in range(len(hashed)):
        out <<= 8
        out |= ord(hashed[i:i + 1])
    return out
