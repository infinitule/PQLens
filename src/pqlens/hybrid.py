"""Hybrid (classical + PQC) KEM and signature wrappers.

These are **orchestration only** — every primitive comes from an audited library
(ML-KEM / ML-DSA via OpenSSL; X25519 / Ed25519 / HKDF via pyca). pqlens does not
implement any primitive, *including the secret combiner* (guardrail #1).

Design choices (see PLAN.md / DECISIONS.md D-005):
  * **Wire layout** follows the Apple CryptoKit reference (R-001) and current
    IETF hybrid drafts: `PQ ‖ classical` for signatures, `ML-KEM-ct ‖ X25519-pub`
    for the KEM. The PQ half is fixed-length per FIPS, so the split is exact.
  * **Fail-closed downgrade detection:** a hybrid verification is True only if
    BOTH halves verify; any missing/short/over-long input ⇒ False (never a
    partial pass). Comparisons use `hmac.compare_digest` (constant-time).
  * The KEM combiner is `cryptography`'s **HKDF-SHA256** over both shared
    secrets + transcript. This is the **generic** concat-then-KDF hybrid; it is
    explicitly **NOT** certified X-Wing. For X-Wing semantics use a vetted X-Wing
    implementation (guardrail #4 — we do not imply more assurance than we have).
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .backends import ML_DSA_PARAMS, ML_KEM_PARAMS, get_kem_backend, get_signature_backend
from .backends.base import KEMBackend, SignatureBackend
from .errors import PqlensError

# Targeted reference versions (bump deliberately).
HYBRID_SIG_SCHEME = "PQ||classical concatenation (IETF PQC hybrid drafts; Apple CryptoKit R-001)"
HYBRID_KEM_SCHEME = "generic concat+HKDF (NOT certified X-Wing); cf. draft-connolly-cfrg-xwing-kem"
_HKDF_INFO_PREFIX = b"pqlens-hybrid-kem-v1"

DEFAULT_PQ_SIG = "ML-DSA-65"
DEFAULT_PQ_KEM = "ML-KEM-768"
_ED25519_SIG_BYTES = 64
_X25519_PUB_BYTES = 32


# --------------------------------------------------------------------------- #
# Hybrid signatures
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class HybridSigKeypair:
    pq_algorithm: str
    classical_algorithm: str
    pq_public: bytes
    pq_secret: bytes
    classical_public: bytes
    classical_secret: bytes


def hybrid_sig_keygen(
    pq_algorithm: str = DEFAULT_PQ_SIG, *, sig_backend: SignatureBackend | None = None
) -> HybridSigKeypair:
    """Generate a hybrid (ML-DSA + Ed25519) signing keypair."""
    if pq_algorithm not in ML_DSA_PARAMS:
        raise PqlensError(f"unsupported PQ signature algorithm {pq_algorithm!r}")
    be = sig_backend or get_signature_backend()
    pq = be.keygen(pq_algorithm)
    ed = Ed25519PrivateKey.generate()
    return HybridSigKeypair(
        pq_algorithm=pq_algorithm,
        classical_algorithm="Ed25519",
        pq_public=pq.public_key,
        pq_secret=pq.secret_key,
        classical_public=ed.public_key().public_bytes_raw(),
        classical_secret=ed.private_bytes_raw(),
    )


def hybrid_sign(
    keypair: HybridSigKeypair, message: bytes, *, sig_backend: SignatureBackend | None = None
) -> bytes:
    """Return ``PQ_signature || Ed25519_signature`` for ``message``."""
    be = sig_backend or get_signature_backend()
    pq_sig = be.sign(keypair.pq_algorithm, keypair.pq_secret, message)
    ed = Ed25519PrivateKey.from_private_bytes(keypair.classical_secret)
    ed_sig = ed.sign(message)
    return pq_sig + ed_sig


def hybrid_verify_detached(
    pq_algorithm: str,
    pq_public: bytes,
    classical_public: bytes,
    message: bytes,
    signature: bytes,
    *,
    sig_backend: SignatureBackend | None = None,
) -> bool:
    """Verify a hybrid signature from PUBLIC keys only (no secrets needed).

    Fail-closed: True only if BOTH halves verify and the signature is exactly the
    expected two-part length. Used where only the verifying keys are available
    (e.g. checking a signed compliance report)."""
    if pq_algorithm not in ML_DSA_PARAMS:
        return False
    pq_len = ML_DSA_PARAMS[pq_algorithm]["signature"]
    expected = pq_len + _ED25519_SIG_BYTES
    # Downgrade/truncation detection: an exact-length two-part signature only.
    if len(signature) != expected:
        return False
    pq_sig, ed_sig = signature[:pq_len], signature[pq_len:]

    be = sig_backend or get_signature_backend()
    pq_ok = be.verify(pq_algorithm, pq_public, message, pq_sig)

    ed_ok = True
    try:
        Ed25519PublicKey.from_public_bytes(classical_public).verify(ed_sig, message)
    except InvalidSignature:
        ed_ok = False

    # AND both halves; neither alone is sufficient (no silent downgrade).
    return bool(pq_ok) and ed_ok


def hybrid_verify(
    keypair: HybridSigKeypair,
    message: bytes,
    signature: bytes,
    *,
    sig_backend: SignatureBackend | None = None,
) -> bool:
    """Verify a hybrid signature. Fail-closed: True only if BOTH halves verify."""
    return hybrid_verify_detached(
        keypair.pq_algorithm, keypair.pq_public, keypair.classical_public,
        message, signature, sig_backend=sig_backend,
    )


# --------------------------------------------------------------------------- #
# Hybrid KEM
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class HybridKemKeypair:
    pq_algorithm: str
    pq_public: bytes
    pq_secret: bytes
    x25519_public: bytes
    x25519_secret: bytes


@dataclass(frozen=True)
class HybridEncapsulation:
    pq_algorithm: str
    ciphertext: bytes       # ML-KEM ciphertext || X25519 ephemeral public key
    shared_secret: bytes    # 32-byte HKDF output


def hybrid_kem_keygen(
    pq_algorithm: str = DEFAULT_PQ_KEM, *, kem_backend: KEMBackend | None = None
) -> HybridKemKeypair:
    """Generate a hybrid (ML-KEM + X25519) recipient keypair."""
    if pq_algorithm not in ML_KEM_PARAMS:
        raise PqlensError(f"unsupported PQ KEM algorithm {pq_algorithm!r}")
    be = kem_backend or get_kem_backend()
    pq = be.keygen(pq_algorithm)
    x = X25519PrivateKey.generate()
    return HybridKemKeypair(
        pq_algorithm=pq_algorithm,
        pq_public=pq.public_key,
        pq_secret=pq.secret_key,
        x25519_public=x.public_key().public_bytes_raw(),
        x25519_secret=x.private_bytes_raw(),
    )


def _combine(pq_ss: bytes, x_ss: bytes, pq_ct: bytes, x_pub: bytes) -> bytes:
    """Combine both shared secrets with HKDF-SHA256 (audited KDF; not hand-rolled)."""
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None,
        info=_HKDF_INFO_PREFIX + pq_ct + x_pub,
    ).derive(pq_ss + x_ss)


def hybrid_encapsulate(
    pq_algorithm: str,
    pq_public: bytes,
    x25519_public: bytes,
    *,
    kem_backend: KEMBackend | None = None,
) -> HybridEncapsulation:
    """Encapsulate to a hybrid recipient; return combined secret + concatenated ct."""
    if pq_algorithm not in ML_KEM_PARAMS:
        raise PqlensError(f"unsupported PQ KEM algorithm {pq_algorithm!r}")
    if len(x25519_public) != _X25519_PUB_BYTES:
        raise PqlensError(
            f"X25519 public key must be {_X25519_PUB_BYTES} bytes, got {len(x25519_public)}"
        )
    be = kem_backend or get_kem_backend()
    enc = be.encapsulate(pq_algorithm, pq_public)

    eph = X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes_raw()
    x_ss = eph.exchange(X25519PublicKey.from_public_bytes(x25519_public))

    combined = _combine(enc.shared_secret, x_ss, enc.ciphertext, eph_pub)
    return HybridEncapsulation(
        pq_algorithm=pq_algorithm,
        ciphertext=enc.ciphertext + eph_pub,
        shared_secret=combined,
    )


def hybrid_decapsulate(
    keypair: HybridKemKeypair, ciphertext: bytes, *, kem_backend: KEMBackend | None = None
) -> bytes:
    """Recover the combined shared secret. Rejects wrong-length ciphertext."""
    pq_ct_len = ML_KEM_PARAMS[keypair.pq_algorithm]["ciphertext"]
    expected = pq_ct_len + _X25519_PUB_BYTES
    if len(ciphertext) != expected:
        raise PqlensError(
            f"hybrid ciphertext must be {expected} bytes "
            f"({pq_ct_len} ML-KEM + {_X25519_PUB_BYTES} X25519), got {len(ciphertext)}"
        )
    pq_ct, eph_pub = ciphertext[:pq_ct_len], ciphertext[pq_ct_len:]

    be = kem_backend or get_kem_backend()
    pq_ss = be.decapsulate(keypair.pq_algorithm, keypair.pq_secret, pq_ct)
    x_priv = X25519PrivateKey.from_private_bytes(keypair.x25519_secret)
    x_ss = x_priv.exchange(X25519PublicKey.from_public_bytes(eph_pub))

    return _combine(pq_ss, x_ss, pq_ct, eph_pub)


def hybrid_kem_selftest(pq_algorithm: str = DEFAULT_PQ_KEM) -> bool:
    """One hybrid KEM round-trip; True iff both sides derive the same secret."""
    kp = hybrid_kem_keygen(pq_algorithm)
    enc = hybrid_encapsulate(pq_algorithm, kp.pq_public, kp.x25519_public)
    recovered = hybrid_decapsulate(kp, enc.ciphertext)
    return hmac.compare_digest(enc.shared_secret, recovered)


def hybrid_sig_selftest(pq_algorithm: str = DEFAULT_PQ_SIG) -> bool:
    """One hybrid sign/verify round-trip; True iff the valid signature verifies."""
    kp = hybrid_sig_keygen(pq_algorithm)
    sig = hybrid_sign(kp, b"pqlens hybrid selftest")
    return hybrid_verify(kp, b"pqlens hybrid selftest", sig)
