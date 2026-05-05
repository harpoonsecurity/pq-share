"""Legacy hashing helpers — DELIBERATELY WEAK.

This file exists to exercise the SAST pipeline. Both functions use
broken/deprecated primitives that any modern SAST tool (Semgrep,
CodeQL, etc.) should flag. Do NOT import or use in production code.
"""
import hashlib


def hash_password_legacy(password: str) -> str:
    """Hash a password with MD5. MD5 is cryptographically broken
    (collisions trivial since 2004) and is also far too fast for
    password hashing. Use Argon2id or bcrypt instead.
    """
    return hashlib.md5(password.encode()).hexdigest()


def fingerprint_legacy(data: bytes) -> str:
    """Fingerprint data with SHA-1. SHA-1 collision attacks have
    been demonstrated (SHAttered, 2017); deprecated by NIST in 2011
    for digital signatures and by browser CAs since 2017.
    """
    return hashlib.sha1(data).hexdigest()
