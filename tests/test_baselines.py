"""Classical X25519 baseline tests (binds to pyca/cryptography)."""

from __future__ import annotations

from pqlens.baselines import x25519_exchange_once, x25519_keygen, x25519_sizes


def test_x25519_sizes_match_rfc7748():
    s = x25519_sizes()
    assert s.name == "X25519"
    assert s.public_key_bytes == 32
    assert s.ciphertext_bytes == 32
    assert s.shared_secret_bytes == 32
    assert s.handshake_wire_bytes == 64  # pk out + ephemeral back


def test_x25519_live_exchange_is_32_bytes():
    assert x25519_exchange_once() == 32


def test_x25519_keygen_produces_usable_key():
    priv = x25519_keygen()
    shared = priv.exchange(x25519_keygen().public_key())
    assert len(shared) == 32
