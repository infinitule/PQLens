"""Phase-1 acceptance: a real ML-KEM-768 encap/decap through an audited backend.

These tests exercise the actual system OpenSSL binding. If no audited backend is
available they are skipped (not silently passed) — pqlens never substitutes a
home-grown primitive to make a test green (guardrail #1).
"""

from __future__ import annotations

import hmac

import pytest

from pqlens.backends import ML_KEM_PARAMS, get_kem_backend
from pqlens.errors import BackendUnavailable
from pqlens.kem import kem_roundtrip, kem_roundtrip_selftest


@pytest.fixture(scope="module")
def backend():
    try:
        return get_kem_backend()
    except BackendUnavailable as exc:  # pragma: no cover - env dependent
        pytest.skip(f"no audited KEM backend available: {exc}")


def test_mlkem768_roundtrip_shared_secret_matches(backend):
    """The required smoke test: encapsulate then decapsulate, secrets must agree."""
    keypair = backend.keygen("ML-KEM-768")
    enc = backend.encapsulate("ML-KEM-768", keypair.public_key)
    recovered = backend.decapsulate("ML-KEM-768", keypair.secret_key, enc.ciphertext)

    assert hmac.compare_digest(enc.shared_secret, recovered)
    # Independent sanity check against NIST parameter sizes.
    assert len(enc.shared_secret) == ML_KEM_PARAMS["ML-KEM-768"]["shared_secret"] == 32
    assert len(enc.ciphertext) == ML_KEM_PARAMS["ML-KEM-768"]["ciphertext"] == 1088


@pytest.mark.parametrize("algorithm", sorted(ML_KEM_PARAMS))
def test_all_ml_kem_sizes_are_faithful(backend, algorithm):
    """Every supported ML-KEM size roundtrips and reports the NIST-spec sizes."""
    params = ML_KEM_PARAMS[algorithm]
    keypair = backend.keygen(algorithm)
    enc = backend.encapsulate(algorithm, keypair.public_key)
    recovered = backend.decapsulate(algorithm, keypair.secret_key, enc.ciphertext)

    assert hmac.compare_digest(enc.shared_secret, recovered)
    assert len(enc.shared_secret) == params["shared_secret"]
    assert len(enc.ciphertext) == params["ciphertext"]


def test_tampered_ciphertext_triggers_implicit_rejection(backend):
    """ML-KEM uses *implicit rejection*: a bad ciphertext does not raise; it yields
    a different (pseudo-random) shared secret. We assert we expose that real
    behavior rather than papering over it (guardrail #4)."""
    keypair = backend.keygen("ML-KEM-768")
    enc = backend.encapsulate("ML-KEM-768", keypair.public_key)

    tampered = bytearray(enc.ciphertext)
    tampered[0] ^= 0x01  # flip one bit
    recovered = backend.decapsulate("ML-KEM-768", keypair.secret_key, bytes(tampered))

    assert len(recovered) == 32  # still a well-formed secret...
    assert not hmac.compare_digest(enc.shared_secret, recovered)  # ...but not the real one


def test_high_level_roundtrip_helper(backend):
    result = kem_roundtrip("ML-KEM-768", backend=backend)
    assert result.secrets_match
    assert result.algorithm == "ML-KEM-768"
    assert result.backend == backend.name
    assert result.shared_secret_len == 32
    assert result.ciphertext_len == 1088


def test_selftest_helper_returns_result(backend):
    result = kem_roundtrip_selftest("ML-KEM-768")
    assert result.secrets_match
