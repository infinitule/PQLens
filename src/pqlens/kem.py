"""High-level KEM orchestration.

Thin glue over a :class:`~pqlens.backends.base.KEMBackend`. The point of this
module is *not* to add crypto — it is to give the rest of pqlens (and the smoke
test) one honest, backend-agnostic entry point for a KEM roundtrip.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass

from .backends import Encapsulation, KeyPair, get_kem_backend
from .backends.base import KEMBackend


@dataclass(frozen=True)
class RoundtripResult:
    """Outcome of a full keygen -> encap -> decap cycle, for diagnostics/tests."""

    algorithm: str
    backend: str
    shared_secret_len: int
    ciphertext_len: int
    secrets_match: bool


def kem_roundtrip(
    algorithm: str = "ML-KEM-768",
    *,
    backend: KEMBackend | None = None,
) -> RoundtripResult:
    """Run one keygen/encapsulate/decapsulate cycle through an audited backend.

    Returns a :class:`RoundtripResult`; ``secrets_match`` must be True for a
    correct implementation. Secret-secret equality is compared with
    :func:`hmac.compare_digest` (constant-time) — guardrail #3.
    """
    be = backend or get_kem_backend()
    keypair: KeyPair = be.keygen(algorithm)
    enc: Encapsulation = be.encapsulate(algorithm, keypair.public_key)
    recovered = be.decapsulate(algorithm, keypair.secret_key, enc.ciphertext)
    return RoundtripResult(
        algorithm=algorithm,
        backend=be.name,
        shared_secret_len=len(enc.shared_secret),
        ciphertext_len=len(enc.ciphertext),
        secrets_match=hmac.compare_digest(enc.shared_secret, recovered),
    )


def kem_roundtrip_selftest(algorithm: str = "ML-KEM-768") -> RoundtripResult:
    """Like :func:`kem_roundtrip` but raises if the shared secrets disagree."""
    result = kem_roundtrip(algorithm)
    if not result.secrets_match:
        raise AssertionError(
            f"KEM self-test FAILED: shared secrets differ for {algorithm} "
            f"via backend {result.backend!r}"
        )
    return result
