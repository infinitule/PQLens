"""Audited-implementation backends for pqlens (orchestration only)."""

from __future__ import annotations

from .base import Encapsulation, KEMBackend, KeyPair, SigKeyPair, SignatureBackend
from .openssl import ML_KEM_PARAMS, OpenSSLKEMBackend
from .openssl_sig import ML_DSA_PARAMS, OpenSSLSignatureBackend
from .registry import (
    all_backends,
    available_backends,
    get_kem_backend,
    get_signature_backend,
)

__all__ = [
    "ML_KEM_PARAMS",
    "ML_DSA_PARAMS",
    "Encapsulation",
    "KEMBackend",
    "KeyPair",
    "SigKeyPair",
    "SignatureBackend",
    "OpenSSLKEMBackend",
    "OpenSSLSignatureBackend",
    "all_backends",
    "available_backends",
    "get_kem_backend",
    "get_signature_backend",
]
