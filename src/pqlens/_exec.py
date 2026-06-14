"""Hardened subprocess + scratch-directory helpers for CLI-based backends.

Security notes (guardrails #3, #4):
  * Secret material is **never** placed in ``argv`` — argv is world-readable via
    ``ps``. Backends pass secrets through files inside a private scratch dir.
  * The scratch dir is created with mode 0700 and removed in a ``finally`` so
    key/secret bytes do not linger on disk.
  * No glue code here branches on the *contents* of secret bytes.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path

from .errors import BackendError


@contextmanager
def secure_scratch_dir(prefix: str = "pqlens-") -> Iterator[Path]:
    """Yield a private (0700) temporary directory, recursively removed on exit.

    Use this to hold key/ciphertext/shared-secret files for a CLI binding so the
    bytes never survive the operation.
    """
    path = Path(tempfile.mkdtemp(prefix=prefix))
    try:
        os.chmod(path, 0o700)
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def run(
    argv: Sequence[str],
    *,
    backend: str,
    timeout: float = 30.0,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    """Run a CLI tool, capturing output, raising :class:`BackendError` on failure.

    ``argv`` must contain only non-secret arguments (paths, algorithm names,
    flags). Pass secrets via files written into a :func:`secure_scratch_dir`.

    With ``check=False`` a non-zero exit is returned to the caller instead of
    raising — used by signature *verification*, where a non-zero exit means
    "signature did not verify" (a normal, fail-closed result) rather than an
    operational error.
    """
    try:
        proc = subprocess.run(  # noqa: S603 - argv is a fixed list, no shell
            list(argv),
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:  # the tool itself is missing
        raise BackendError(
            f"executable not found: {argv[0]!r}", backend=backend
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise BackendError(
            f"command timed out after {timeout}s: {argv[0]!r}", backend=backend
        ) from exc

    if check and proc.returncode != 0:
        raise BackendError(
            f"command failed (exit {proc.returncode}): {' '.join(map(str, argv))}",
            backend=backend,
            detail=proc.stderr.decode("utf-8", "replace").strip() or None,
        )
    return proc
