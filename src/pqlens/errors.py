"""Exception hierarchy for pqlens.

Kept tiny and specific so callers can distinguish "no audited backend is
installed" (an environment problem the user can fix) from "the backend ran but
failed" (an operational problem)."""

from __future__ import annotations


class PqlensError(Exception):
    """Base class for every error pqlens raises on purpose."""


class BackendUnavailable(PqlensError):
    """No audited cryptographic backend could be located at runtime.

    pqlens never falls back to a home-grown primitive (guardrail #1); when no
    audited backend is present it refuses to operate and says how to fix it.
    """


class BackendError(PqlensError):
    """An audited backend was found but the operation failed.

    Carries the backend name and, when useful, captured diagnostic output.
    """

    def __init__(self, message: str, *, backend: str | None = None, detail: str | None = None):
        self.backend = backend
        self.detail = detail
        full = message
        if backend:
            full = f"[{backend}] {full}"
        if detail:
            full = f"{full}\n{detail}"
        super().__init__(full)
