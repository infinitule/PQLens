"""Backend registry + error-path tests (no real crypto needed)."""

from __future__ import annotations

import pytest

from pqlens.backends import (
    KEMBackend,
    OpenSSLKEMBackend,
    all_backends,
    available_backends,
    registry,
)
from pqlens.errors import BackendError, BackendUnavailable


def test_openssl_backend_satisfies_protocol():
    be = OpenSSLKEMBackend()
    assert isinstance(be, KEMBackend)  # runtime_checkable Protocol
    assert be.name == "openssl"


def test_all_backends_nonempty():
    assert len(all_backends()) >= 1


def test_get_unknown_backend_raises():
    with pytest.raises(BackendUnavailable, match="unknown backend"):
        registry.get_kem_backend("does-not-exist")


def test_no_available_backend_raises_actionable(monkeypatch):
    """When nothing is available, the public API refuses to operate and explains
    how to fix it — it never falls back to a home-grown primitive."""

    class _Dead(OpenSSLKEMBackend):
        def available(self) -> bool:  # type: ignore[override]
            return False

    monkeypatch.setattr(registry, "_BACKEND_FACTORIES", (_Dead,))
    assert available_backends() == ()
    with pytest.raises(BackendUnavailable, match="no audited KEM backend"):
        registry.get_kem_backend()


def test_named_but_unavailable_backend_raises(monkeypatch):
    class _Dead(OpenSSLKEMBackend):
        def available(self) -> bool:  # type: ignore[override]
            return False

    monkeypatch.setattr(registry, "_BACKEND_FACTORIES", (_Dead,))
    with pytest.raises(BackendUnavailable, match="not available"):
        registry.get_kem_backend("openssl")


def test_unsupported_algorithm_rejected():
    be = OpenSSLKEMBackend()
    with pytest.raises(BackendError, match="unsupported algorithm"):
        be.keygen("RSA-2048")  # not a KEM this backend drives


def test_backend_error_formatting():
    err = BackendError("boom", backend="openssl", detail="stderr line")
    s = str(err)
    assert "[openssl]" in s
    assert "boom" in s
    assert "stderr line" in s


# --- signature backend registry (Phase 4) ---------------------------------- #
def test_get_signature_backend_returns_openssl_when_available():
    from pqlens.backends import OpenSSLSignatureBackend, SignatureBackend
    from pqlens.backends.registry import get_signature_backend

    be = OpenSSLSignatureBackend()
    assert isinstance(be, SignatureBackend)  # runtime_checkable Protocol
    if be.available():
        assert get_signature_backend().name == "openssl"
        assert get_signature_backend("openssl").name == "openssl"
        assert "ML-DSA-65" in be.supported_algorithms()


def test_get_signature_backend_unknown_name_raises():
    from pqlens.backends.registry import get_signature_backend

    with pytest.raises(BackendUnavailable, match="unknown signature backend"):
        get_signature_backend("does-not-exist")


def test_signature_backend_rejects_unsupported_algorithm():
    from pqlens.backends import OpenSSLSignatureBackend

    be = OpenSSLSignatureBackend()
    with pytest.raises(BackendError, match="unsupported algorithm"):
        be.keygen("Dilithium-9000")
