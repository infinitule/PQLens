"""ML-DSA signature backend that orchestrates the system OpenSSL (>= 3.5) CLI.

Orchestration of an audited implementation, not a reimplementation (guardrail
#1). Same on-disk-secret discipline and caveat as the KEM backend: keys/messages
move through a 0700 scratch dir, never ``argv`` (DECISIONS.md D-003).

Verified flow (OpenSSL 3.6.2, ML-DSA-65 -> 3309-byte signature)::

    openssl genpkey -algorithm ML-DSA-65 -out priv.pem
    openssl pkey -in priv.pem -pubout -out pub.pem
    openssl pkeyutl -sign   -inkey priv.pem -rawin -in msg -out sig
    openssl pkeyutl -verify -inkey pub.pem -pubin -rawin -in msg -sigfile sig
"""

from __future__ import annotations

from .._exec import run, secure_scratch_dir
from ..errors import BackendError
from .base import SigKeyPair
from .openssl import (  # reuse version probe + path resolution
    OpenSSLKEMBackend,
    _openssl_version,
)

# ML-DSA signature sizes (FIPS 204) — used as an independent sanity check and to
# split the hybrid signature wire format. Public constants, not secrets.
ML_DSA_PARAMS: dict[str, dict[str, int]] = {
    "ML-DSA-44": {"signature": 2420, "public_key": 1312},
    "ML-DSA-65": {"signature": 3309, "public_key": 1952},
    "ML-DSA-87": {"signature": 4627, "public_key": 2592},
}

_MIN_OPENSSL = (3, 5)


class OpenSSLSignatureBackend:
    """Signature backend backed by the system ``openssl`` binary."""

    name = "openssl"

    # Reuse the KEM backend's resolved path/availability logic to avoid drift.
    _kem = OpenSSLKEMBackend()

    def available(self) -> bool:
        ver = _openssl_version()
        return ver is not None and ver[:2] >= _MIN_OPENSSL

    def supported_algorithms(self) -> tuple[str, ...]:
        return tuple(ML_DSA_PARAMS) if self.available() else ()

    def _exe(self) -> str:
        # Delegate to the KEM backend's identical resolution + error message.
        return self._kem._exe()

    @staticmethod
    def _check_algo(algorithm: str) -> None:
        if algorithm not in ML_DSA_PARAMS:
            raise BackendError(
                f"unsupported algorithm {algorithm!r}; "
                f"this backend supports {', '.join(ML_DSA_PARAMS)}",
                backend="openssl",
            )

    def keygen(self, algorithm: str) -> SigKeyPair:
        self._check_algo(algorithm)
        exe = self._exe()
        with secure_scratch_dir() as d:
            priv, pub = d / "priv.pem", d / "pub.pem"
            run([exe, "genpkey", "-algorithm", algorithm, "-out", str(priv)],
                backend=self.name)
            run([exe, "pkey", "-in", str(priv), "-pubout", "-out", str(pub)],
                backend=self.name)
            return SigKeyPair(algorithm=algorithm,
                              public_key=pub.read_bytes(),
                              secret_key=priv.read_bytes())

    def sign(self, algorithm: str, secret_key: bytes, message: bytes) -> bytes:
        self._check_algo(algorithm)
        exe = self._exe()
        with secure_scratch_dir() as d:
            priv, msg, sig = d / "priv.pem", d / "msg.bin", d / "sig.bin"
            priv.write_bytes(secret_key)
            msg.write_bytes(message)
            run([exe, "pkeyutl", "-sign", "-inkey", str(priv), "-rawin",
                 "-in", str(msg), "-out", str(sig)], backend=self.name)
            return sig.read_bytes()

    def verify(self, algorithm: str, public_key: bytes, message: bytes,
               signature: bytes) -> bool:
        """Fail-closed verification: True only on a clean exit-0 from OpenSSL."""
        self._check_algo(algorithm)
        exe = self._exe()
        with secure_scratch_dir() as d:
            pub, msg, sig = d / "pub.pem", d / "msg.bin", d / "sig.bin"
            pub.write_bytes(public_key)
            msg.write_bytes(message)
            sig.write_bytes(signature)
            proc = run(
                [exe, "pkeyutl", "-verify", "-inkey", str(pub), "-pubin",
                 "-rawin", "-in", str(msg), "-sigfile", str(sig)],
                backend=self.name, check=False,
            )
            return proc.returncode == 0
