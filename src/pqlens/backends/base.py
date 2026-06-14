"""The KEM backend contract.

A *backend* is a thin adapter over an **audited** KEM implementation (OpenSSL,
liboqs, ...). pqlens orchestrates these; it never implements the KEM itself
(guardrail #1). Keeping the surface to three verbs (keygen / encapsulate /
decapsulate) means any audited KEM provider can be dropped in without touching
the rest of the library.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class KeyPair:
    """A KEM key pair, as opaque bytes produced by an audited backend.

    ``secret_key`` is sensitive. We do not branch on its contents anywhere in
    glue code (guardrail #3); we only move it between the backend and the user.
    """

    algorithm: str
    public_key: bytes
    secret_key: bytes


@dataclass(frozen=True)
class Encapsulation:
    """Result of encapsulating to a public key."""

    algorithm: str
    ciphertext: bytes
    shared_secret: bytes


@dataclass(frozen=True)
class SigKeyPair:
    """A signature key pair, as opaque bytes produced by an audited backend."""

    algorithm: str
    public_key: bytes
    secret_key: bytes


@runtime_checkable
class KEMBackend(Protocol):
    """Protocol every KEM backend implements.

    Implementations must faithfully expose the primitive's real behavior — e.g.
    ML-KEM's *implicit rejection* (decapsulating a bad ciphertext yields a
    pseudo-random secret rather than an error). We do not paper over that.
    """

    #: Stable short identifier, e.g. ``"openssl"`` or ``"liboqs"``.
    name: str

    def available(self) -> bool:
        """Return True iff this backend can actually run in this environment."""
        ...

    def supported_algorithms(self) -> tuple[str, ...]:
        """KEM algorithm names this backend can run (e.g. ``"ML-KEM-768"``)."""
        ...

    def keygen(self, algorithm: str) -> KeyPair:
        """Generate a fresh key pair for ``algorithm``."""
        ...

    def encapsulate(self, algorithm: str, public_key: bytes) -> Encapsulation:
        """Encapsulate a shared secret to ``public_key``."""
        ...

    def decapsulate(self, algorithm: str, secret_key: bytes, ciphertext: bytes) -> bytes:
        """Recover the shared secret from ``ciphertext`` using ``secret_key``."""
        ...


@runtime_checkable
class SignatureBackend(Protocol):
    """Protocol every signature backend implements (e.g. ML-DSA via OpenSSL).

    ``verify`` is **fail-closed**: it returns False for any non-success,
    including malformed inputs, rather than raising — so a hybrid wrapper can
    AND-combine two verifications and reject on any partial failure.
    """

    name: str

    def available(self) -> bool:
        ...

    def supported_algorithms(self) -> tuple[str, ...]:
        ...

    def keygen(self, algorithm: str) -> SigKeyPair:
        ...

    def sign(self, algorithm: str, secret_key: bytes, message: bytes) -> bytes:
        ...

    def verify(self, algorithm: str, public_key: bytes, message: bytes, signature: bytes) -> bool:
        ...
