"""ML-KEM backend that orchestrates the system OpenSSL (>= 3.5) CLI.

This is an *orchestration* of an audited implementation, not a reimplementation
(guardrail #1). Keys, ciphertexts and shared secrets move through files in a
private 0700 scratch dir (see ``_exec.secure_scratch_dir``) and never appear in
``argv`` (guardrail #3/#4, DECISIONS.md D-003).

Verified flow (OpenSSL 3.6.2)::

    openssl genpkey -algorithm ML-KEM-768 -out priv.pem
    openssl pkey -in priv.pem -pubout -out pub.pem
    openssl pkeyutl -encap -inkey pub.pem -pubin -secret ssA.bin -out ct.bin
    openssl pkeyutl -decap -inkey priv.pem -secret ssB.bin -in ct.bin
"""

from __future__ import annotations

import os
import re
import shutil
from functools import lru_cache

from .._exec import run, secure_scratch_dir
from ..errors import BackendError
from .base import Encapsulation, KeyPair

#: Algorithms this backend knows how to drive, with their NIST parameter sizes
#: (bytes). Sizes are used by the test-suite as an independent sanity check and
#: by the Phase-2 measurement core; they are public constants, not secrets.
ML_KEM_PARAMS: dict[str, dict[str, int]] = {
    "ML-KEM-512": {"shared_secret": 32, "ciphertext": 768},
    "ML-KEM-768": {"shared_secret": 32, "ciphertext": 1088},
    "ML-KEM-1024": {"shared_secret": 32, "ciphertext": 1568},
}

_MIN_OPENSSL = (3, 5)


@lru_cache(maxsize=1)
def _openssl_path() -> str | None:
    return os.environ.get("PQLENS_OPENSSL") or shutil.which("openssl")


@lru_cache(maxsize=1)
def _openssl_version() -> tuple[int, int, int] | None:
    """Return the (major, minor, patch) of the system openssl, or None."""
    exe = _openssl_path()
    if not exe:
        return None
    try:
        proc = run([exe, "version"], backend="openssl")
    except BackendError:
        return None
    m = re.search(rb"OpenSSL\s+(\d+)\.(\d+)\.(\d+)", proc.stdout)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


class OpenSSLKEMBackend:
    """KEM backend backed by the system ``openssl`` binary."""

    name = "openssl"

    def available(self) -> bool:
        ver = _openssl_version()
        return ver is not None and ver[:2] >= _MIN_OPENSSL

    def supported_algorithms(self) -> tuple[str, ...]:
        return tuple(ML_KEM_PARAMS) if self.available() else ()

    # -- internal helpers -------------------------------------------------

    def _exe(self) -> str:
        exe = _openssl_path()
        if exe is None or not self.available():
            ver = _openssl_version()
            raise BackendError(
                f"system openssl >= {_MIN_OPENSSL[0]}.{_MIN_OPENSSL[1]} required "
                f"for ML-KEM (found {ver}). Set PQLENS_OPENSSL to a suitable binary.",
                backend=self.name,
            )
        return exe

    @staticmethod
    def _check_algo(algorithm: str) -> None:
        if algorithm not in ML_KEM_PARAMS:
            raise BackendError(
                f"unsupported algorithm {algorithm!r}; "
                f"this backend supports {', '.join(ML_KEM_PARAMS)}",
                backend="openssl",
            )

    # -- KEMBackend protocol ----------------------------------------------

    def keygen(self, algorithm: str) -> KeyPair:
        self._check_algo(algorithm)
        exe = self._exe()
        with secure_scratch_dir() as d:
            priv = d / "priv.pem"
            pub = d / "pub.pem"
            run([exe, "genpkey", "-algorithm", algorithm, "-out", str(priv)],
                backend=self.name)
            run([exe, "pkey", "-in", str(priv), "-pubout", "-out", str(pub)],
                backend=self.name)
            return KeyPair(
                algorithm=algorithm,
                public_key=pub.read_bytes(),
                secret_key=priv.read_bytes(),
            )

    def encapsulate(self, algorithm: str, public_key: bytes) -> Encapsulation:
        self._check_algo(algorithm)
        exe = self._exe()
        with secure_scratch_dir() as d:
            pub = d / "pub.pem"
            ss = d / "ss.bin"
            ct = d / "ct.bin"
            pub.write_bytes(public_key)
            run([exe, "pkeyutl", "-encap", "-inkey", str(pub), "-pubin",
                 "-secret", str(ss), "-out", str(ct)], backend=self.name)
            return Encapsulation(
                algorithm=algorithm,
                ciphertext=ct.read_bytes(),
                shared_secret=ss.read_bytes(),
            )

    def decapsulate(self, algorithm: str, secret_key: bytes, ciphertext: bytes) -> bytes:
        self._check_algo(algorithm)
        exe = self._exe()
        with secure_scratch_dir() as d:
            priv = d / "priv.pem"
            ss = d / "ss.bin"
            ct = d / "ct.bin"
            priv.write_bytes(secret_key)
            ct.write_bytes(ciphertext)
            run([exe, "pkeyutl", "-decap", "-inkey", str(priv),
                 "-secret", str(ss), "-in", str(ct)], backend=self.name)
            return ss.read_bytes()
