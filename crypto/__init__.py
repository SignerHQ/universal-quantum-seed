# Copyright (c) 2026 Signer — MIT License

"""Post-quantum cryptography modules.

ML-DSA-65 (FIPS 204) — lattice-based digital signature, NIST Level 3.
SLH-DSA-SHAKE-128s (FIPS 205) — hash-based digital signature, NIST Level 1.
ML-KEM-768 (FIPS 203) — lattice-based key encapsulation, NIST Level 3.
"""

from .ml_dsa import ml_keygen, ml_sign, ml_verify
from .slh_dsa import slh_keygen, slh_sign, slh_verify
from .ml_kem import ml_kem_keygen, ml_kem_encaps, ml_kem_decaps

__all__ = [
    "ml_keygen", "ml_sign", "ml_verify",
    "slh_keygen", "slh_sign", "slh_verify",
    "ml_kem_keygen", "ml_kem_encaps", "ml_kem_decaps",
]
