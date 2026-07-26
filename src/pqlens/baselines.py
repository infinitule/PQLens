"""Classical baseline (X25519) via pyca/cryptography.

The migration-cost model needs a *classical reference* to measure PQC against.
X25519 is the standard ECDH baseline (RFC 7748). This module only **binds to**
``cryptography`` — it implements nothing (guardrail #1). It provides the real
ephemeral exchange so the baseline timing is measured, not guessed.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


@dataclass(frozen=True)
class BaselineSizes:
    name: str
    public_key_bytes: int
    ciphertext_bytes: int
    shared_secret_bytes: int

    @property
    def handshake_wire_bytes(self) -> int:
        """Bytes on the wire for one ephemeral exchange: pk (out) + ct (back)."""
        return self.public_key_bytes + self.ciphertext_bytes


def x25519_sizes() -> BaselineSizes:
    """RFC 7748 sizes. ``ciphertext`` = the responder's 32-byte ephemeral key."""
    return BaselineSizes(
        name="X25519",
        public_key_bytes=32,
        ciphertext_bytes=32,
        shared_secret_bytes=32,
    )


def x25519_keygen() -> X25519PrivateKey:
    """Generate an ephemeral X25519 private key (audited RNG inside cryptography)."""
    return X25519PrivateKey.generate()


def x25519_exchange_once() -> int:
    """Perform one full ephemeral X25519 exchange; return shared-secret length.

    Used to time the classical baseline on the same machine as the PQC path.
    Note: this is **in-process** (no subprocess), unlike the OpenSSL-CLI KEM
    backend — see ``measure`` for why the two timings are not directly
    comparable and why pqlens headlines size deltas instead.
    """
    alice = X25519PrivateKey.generate()
    bob = X25519PrivateKey.generate()
    shared = alice.exchange(bob.public_key())
    return len(shared)
