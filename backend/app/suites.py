"""
Cipher suite schema for pq-share.

Captures the user's selection from the picker and validates that it represents
a legal combination. The schema is the contract the frontend builds against,
the wire format on upload, and the persisted record on each File row.

Design notes:
- Posture tier ("classical" / "hybrid" / "pqc" / "cnsa") is derived from the
  primitives, not stored — there's exactly one right answer per primitive set.
- Overhead bytes are similarly derived (and approximate); the server is the
  source of truth for what gets shown to recipients.
- Preset is just a label hinting at the user's intent. Server-side validation
  treats "custom" as anything-goes (within TLS-version constraints) and
  treats every other preset as a hard lock to its spec.
"""
from __future__ import annotations

from typing import Literal, get_args

from pydantic import BaseModel, ConfigDict, model_validator


# ---- Primitive vocabularies (mirrored in frontend/picker.js) -----------------

PresetName = Literal["custom", "nist-800-52", "fips-140-3-hybrid", "pqc-only", "cnsa-2"]
TlsVersion = Literal["1.2", "1.3"]
PostureTier = Literal["classical", "hybrid", "pqc", "cnsa"]

RngAlg = Literal["HMAC-DRBG-SHA256", "AES-CTR-DRBG-256", "HMAC-DRBG-SHA512"]
KexAlg = Literal["X25519", "secp384r1", "X25519MLKEM768", "ML-KEM-768", "ML-KEM-1024"]
HashAlg = Literal["SHA-256", "SHA-384", "SHA-512", "SHA3-512"]
SymAlg = Literal["AES-128-GCM", "AES-256-GCM", "ChaCha20-Poly1305", "AES-256-GCM-SIV"]
SigAlg = Literal[
    "Ed25519", "ECDSA-P384", "Ed25519+ML-DSA-65", "ML-DSA-65", "ML-DSA-87"
]


# ---- Tier classification -----------------------------------------------------

TIER_OF: dict[str, PostureTier] = {
    # RNG
    "HMAC-DRBG-SHA256":   "hybrid",
    "AES-CTR-DRBG-256":   "hybrid",
    "HMAC-DRBG-SHA512":   "pqc",
    # KEX
    "X25519":             "classical",
    "secp384r1":          "classical",
    "X25519MLKEM768":     "hybrid",
    "ML-KEM-768":         "pqc",
    "ML-KEM-1024":        "cnsa",
    # Hash
    "SHA-256":            "classical",
    "SHA-384":            "hybrid",
    "SHA-512":            "hybrid",
    "SHA3-512":           "pqc",
    # Symmetric
    "AES-128-GCM":        "classical",
    "AES-256-GCM":        "hybrid",
    "ChaCha20-Poly1305":  "hybrid",
    "AES-256-GCM-SIV":    "pqc",
    # Signature
    "Ed25519":            "classical",
    "ECDSA-P384":         "classical",
    "Ed25519+ML-DSA-65":  "hybrid",
    "ML-DSA-65":          "pqc",
    "ML-DSA-87":          "cnsa",
}

_TIER_RANK = {"classical": 0, "hybrid": 1, "pqc": 2, "cnsa": 3}

# Tier each preset establishes when applied. "Custom" has no fixed tier and
# falls back to weakest-link aggregation across primitives.
_PRESET_TIER: dict[str, PostureTier] = {
    "nist-800-52":       "classical",
    "fips-140-3-hybrid": "hybrid",
    "pqc-only":          "pqc",
    "cnsa-2":            "cnsa",
}


# ---- Preset locks ------------------------------------------------------------

PRESET_LOCKS: dict[str, dict[str, str]] = {
    "nist-800-52": {
        "tls": "1.2", "rng": "AES-CTR-DRBG-256", "kex": "secp384r1",
        "hash": "SHA-384", "sym": "AES-256-GCM", "sig": "ECDSA-P384",
    },
    "fips-140-3-hybrid": {
        "tls": "1.3", "rng": "AES-CTR-DRBG-256", "kex": "X25519MLKEM768",
        "hash": "SHA-384", "sym": "AES-256-GCM", "sig": "Ed25519+ML-DSA-65",
    },
    "pqc-only": {
        "tls": "1.3", "rng": "HMAC-DRBG-SHA512", "kex": "ML-KEM-768",
        "hash": "SHA3-512", "sym": "AES-256-GCM", "sig": "ML-DSA-65",
    },
    "cnsa-2": {
        "tls": "1.3", "rng": "AES-CTR-DRBG-256", "kex": "ML-KEM-1024",
        "hash": "SHA-512", "sym": "AES-256-GCM", "sig": "ML-DSA-87",
    },
}

# TLS 1.2 cannot carry these — pure-PQ and most PQ-hybrid groups are TLS 1.3 only.
TLS12_FORBIDDEN_KEX: frozenset[str] = frozenset({"X25519MLKEM768", "ML-KEM-768", "ML-KEM-1024"})
TLS12_FORBIDDEN_SIG: frozenset[str] = frozenset({"Ed25519+ML-DSA-65", "ML-DSA-65", "ML-DSA-87"})


# ---- Schema ------------------------------------------------------------------

class CryptoSuite(BaseModel):
    """Validated cipher-suite selection. Round-trips via JSON."""

    model_config = ConfigDict(extra="forbid")

    preset: PresetName
    tls: TlsVersion
    rng: RngAlg
    kex: KexAlg
    hash: HashAlg
    sym: SymAlg
    sig: SigAlg

    @model_validator(mode="after")
    def _enforce_preset_and_tls(self) -> "CryptoSuite":
        # If a non-custom preset is claimed, every primitive must match its lock.
        lock = PRESET_LOCKS.get(self.preset)
        if lock is not None:
            mismatches = [
                f"{k}={getattr(self, k)!r} (preset requires {v!r})"
                for k, v in lock.items()
                if getattr(self, k) != v
            ]
            if mismatches:
                raise ValueError(
                    f"preset {self.preset!r} mismatch: " + "; ".join(mismatches)
                )

        # TLS 1.2 carries neither PQ KEX nor PQ signatures.
        if self.tls == "1.2":
            if self.kex in TLS12_FORBIDDEN_KEX:
                raise ValueError(f"kex {self.kex!r} requires TLS 1.3")
            if self.sig in TLS12_FORBIDDEN_SIG:
                raise ValueError(f"sig {self.sig!r} requires TLS 1.3")

        return self

    # ---- Derived properties (recomputed; not stored) ------------------------

    @property
    def posture_tier(self) -> PostureTier:
        """Posture: preset tier if a preset is applied, else weakest-link aggregate.

        Rationale: a user who picks "CNSA 2.0" expects the badge to say CNSA,
        even though SHA-512 / AES-256-GCM individually live at "hybrid" tier in
        the natural-home tier map. The preset is the regulatory claim; honor it.
        """
        if self.preset in _PRESET_TIER:
            return _PRESET_TIER[self.preset]
        tiers = [TIER_OF[getattr(self, k)] for k in ("rng", "kex", "hash", "sym", "sig")]
        return min(tiers, key=lambda t: _TIER_RANK[t])

    @property
    def overhead_bytes(self) -> int:
        """Rough estimate: handshake key share + signature + AEAD framing."""
        ks = {
            "X25519": 32, "secp384r1": 97, "X25519MLKEM768": 1216,
            "ML-KEM-768": 1184, "ML-KEM-1024": 1568,
        }.get(self.kex, 0)
        sig = {
            "Ed25519": 64, "ECDSA-P384": 96, "Ed25519+ML-DSA-65": 3373,
            "ML-DSA-65": 3309, "ML-DSA-87": 4627,
        }.get(self.sig, 0)
        return ks + sig + 64 + 96  # 64B transcript + 96B AEAD framing

    def with_derived(self) -> dict:
        """Serialization including the derived posture & overhead, for clients."""
        return {
            **self.model_dump(),
            "posture_tier": self.posture_tier,
            "overhead_bytes": self.overhead_bytes,
        }


# Used by tests / introspection — not stable API.
def all_primitives() -> dict[str, tuple[str, ...]]:
    return {
        "rng": get_args(RngAlg),
        "kex": get_args(KexAlg),
        "hash": get_args(HashAlg),
        "sym": get_args(SymAlg),
        "sig": get_args(SigAlg),
    }
