"""Phase-4 acceptance tests for hybrid KEM + signature wrappers.

These exercise real OpenSSL ML-KEM/ML-DSA + pyca X25519/Ed25519. If no audited
backend is available they skip (pqlens never substitutes a home-grown primitive).
"""

from __future__ import annotations

import hmac

import pytest

from pqlens.backends import ML_DSA_PARAMS, ML_KEM_PARAMS, available_backends
from pqlens.errors import PqlensError
from pqlens.hybrid import (
    hybrid_decapsulate,
    hybrid_encapsulate,
    hybrid_kem_keygen,
    hybrid_kem_selftest,
    hybrid_sig_keygen,
    hybrid_sig_selftest,
    hybrid_sign,
    hybrid_verify,
)

HAVE_BACKEND = len(available_backends()) > 0
pytestmark = pytest.mark.skipif(not HAVE_BACKEND, reason="no audited backend")

MSG = b"pqlens phase-4 hybrid message"


# --- hybrid signature: round-trip + fail-closed downgrade detection (acc #1) -- #
def test_hybrid_signature_roundtrip():
    kp = hybrid_sig_keygen("ML-DSA-65")
    sig = hybrid_sign(kp, MSG)
    assert len(sig) == ML_DSA_PARAMS["ML-DSA-65"]["signature"] + 64
    assert hybrid_verify(kp, MSG, sig) is True


def test_hybrid_signature_rejects_tampered_pq_half():
    kp = hybrid_sig_keygen("ML-DSA-65")
    sig = bytearray(hybrid_sign(kp, MSG))
    sig[0] ^= 0x01  # flip a bit in the PQ (ML-DSA) half
    assert hybrid_verify(kp, MSG, bytes(sig)) is False


def test_hybrid_signature_rejects_tampered_classical_half():
    kp = hybrid_sig_keygen("ML-DSA-65")
    sig = bytearray(hybrid_sign(kp, MSG))
    sig[-1] ^= 0x01  # flip a bit in the Ed25519 half
    assert hybrid_verify(kp, MSG, bytes(sig)) is False


def test_hybrid_signature_rejects_downgrade_to_one_half():
    """Only the PQ half present (truncated) must NOT verify — no silent downgrade."""
    kp = hybrid_sig_keygen("ML-DSA-65")
    sig = hybrid_sign(kp, MSG)
    pq_only = sig[: ML_DSA_PARAMS["ML-DSA-65"]["signature"]]
    classical_only = sig[ML_DSA_PARAMS["ML-DSA-65"]["signature"] :]
    assert hybrid_verify(kp, MSG, pq_only) is False
    assert hybrid_verify(kp, MSG, classical_only) is False


def test_hybrid_signature_rejects_wrong_message():
    kp = hybrid_sig_keygen("ML-DSA-65")
    sig = hybrid_sign(kp, MSG)
    assert hybrid_verify(kp, b"a different message", sig) is False


def test_hybrid_sig_selftest_helper():
    assert hybrid_sig_selftest("ML-DSA-65") is True


# --- hybrid KEM: round-trip + tamper (acc #2) ------------------------------- #
def test_hybrid_kem_roundtrip_same_secret():
    kp = hybrid_kem_keygen("ML-KEM-768")
    enc = hybrid_encapsulate("ML-KEM-768", kp.pq_public, kp.x25519_public)
    recovered = hybrid_decapsulate(kp, enc.ciphertext)
    assert hmac.compare_digest(enc.shared_secret, recovered)
    assert len(enc.shared_secret) == 32
    # ciphertext = ML-KEM ct || X25519 pub
    assert len(enc.ciphertext) == ML_KEM_PARAMS["ML-KEM-768"]["ciphertext"] + 32


def test_hybrid_kem_corrupting_pq_component_changes_secret():
    kp = hybrid_kem_keygen("ML-KEM-768")
    enc = hybrid_encapsulate("ML-KEM-768", kp.pq_public, kp.x25519_public)
    ct = bytearray(enc.ciphertext)
    ct[0] ^= 0x01  # corrupt ML-KEM ciphertext half
    recovered = hybrid_decapsulate(kp, bytes(ct))
    assert not hmac.compare_digest(enc.shared_secret, recovered)


def test_hybrid_kem_corrupting_x25519_component_changes_secret():
    kp = hybrid_kem_keygen("ML-KEM-768")
    enc = hybrid_encapsulate("ML-KEM-768", kp.pq_public, kp.x25519_public)
    ct = bytearray(enc.ciphertext)
    ct[-1] ^= 0x01  # corrupt X25519 ephemeral public half
    recovered = hybrid_decapsulate(kp, bytes(ct))
    assert not hmac.compare_digest(enc.shared_secret, recovered)


def test_hybrid_kem_selftest_helper():
    assert hybrid_kem_selftest("ML-KEM-768") is True


# --- error paths (acc #3) --------------------------------------------------- #
def test_hybrid_decapsulate_rejects_wrong_length_ciphertext():
    kp = hybrid_kem_keygen("ML-KEM-768")
    with pytest.raises(PqlensError, match="hybrid ciphertext must be"):
        hybrid_decapsulate(kp, b"too short")


def test_hybrid_encapsulate_rejects_bad_x25519_pubkey():
    kp = hybrid_kem_keygen("ML-KEM-768")
    with pytest.raises(PqlensError, match="X25519 public key must be"):
        hybrid_encapsulate("ML-KEM-768", kp.pq_public, b"\x00" * 10)


def test_hybrid_keygen_rejects_unknown_algorithms():
    with pytest.raises(PqlensError, match="unsupported PQ signature"):
        hybrid_sig_keygen("ML-DSA-999")
    with pytest.raises(PqlensError, match="unsupported PQ KEM"):
        hybrid_kem_keygen("ML-KEM-999")
