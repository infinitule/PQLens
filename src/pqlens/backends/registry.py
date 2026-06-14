"""Runtime discovery of *available* audited KEM backends.

pqlens refuses to operate without an audited backend rather than silently
falling back to anything home-grown (guardrail #1). The registry is the single
place that knows the preference order and reports, honestly, what is installed.
"""

from __future__ import annotations

from ..errors import BackendUnavailable
from .base import KEMBackend, SignatureBackend
from .openssl import OpenSSLKEMBackend
from .openssl_sig import OpenSSLSignatureBackend

# Preference order. OpenSSL first (verified present); liboqs would slot in ahead
# of it once wired (in-memory, see DECISIONS.md D-002) — left out until real.
_BACKEND_FACTORIES = (
    OpenSSLKEMBackend,
)

_SIGNATURE_FACTORIES = (
    OpenSSLSignatureBackend,
)


def all_backends() -> tuple[KEMBackend, ...]:
    """Instantiate every known backend (whether or not it is available)."""
    return tuple(factory() for factory in _BACKEND_FACTORIES)


def available_backends() -> tuple[KEMBackend, ...]:
    """Return only the backends that can actually run in this environment."""
    return tuple(b for b in all_backends() if b.available())


def get_kem_backend(name: str | None = None) -> KEMBackend:
    """Return an available KEM backend.

    With ``name`` given, return that specific backend or raise. Without a name,
    return the most-preferred available backend, or raise
    :class:`BackendUnavailable` with an actionable message.
    """
    backends = all_backends()
    if name is not None:
        for b in backends:
            if b.name == name:
                if not b.available():
                    raise BackendUnavailable(
                        f"backend {name!r} is known but not available in this "
                        f"environment. Install/configure it and retry."
                    )
                return b
        raise BackendUnavailable(
            f"unknown backend {name!r}; known: {', '.join(b.name for b in backends)}"
        )

    for b in backends:
        if b.available():
            return b
    raise BackendUnavailable(
        "no audited KEM backend is available. pqlens will not fall back to a "
        "home-grown primitive. Install OpenSSL >= 3.5 (provides ML-KEM), or "
        "`pip install pqlens[liboqs]`."
    )


def get_signature_backend(name: str | None = None) -> SignatureBackend:
    """Return an available signature backend (ML-DSA), or raise.

    Mirrors :func:`get_kem_backend`; refuses to fall back to a home-grown
    primitive when none is available.
    """
    backends = tuple(factory() for factory in _SIGNATURE_FACTORIES)
    if name is not None:
        for b in backends:
            if b.name == name:
                if not b.available():
                    raise BackendUnavailable(
                        f"signature backend {name!r} is known but not available."
                    )
                return b
        raise BackendUnavailable(
            f"unknown signature backend {name!r}; "
            f"known: {', '.join(b.name for b in backends)}"
        )
    for b in backends:
        if b.available():
            return b
    raise BackendUnavailable(
        "no audited signature backend is available. Install OpenSSL >= 3.5 "
        "(provides ML-DSA)."
    )
