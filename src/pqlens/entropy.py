"""Entropy diagnostics — MEASUREMENT ONLY.

pqlens **measures and health-tests a sample of randomness the caller already
captured**. It is *not* a random number generator and must never be used as one
(guardrail #2). That line is designed into the API, not merely documented:

  * This module imports **no** RNG — there is intentionally no ``import os`` /
    ``secrets`` / ``random`` here.
  * No function generates, seeds, or returns random bytes. Every public function
    takes a sample (or a probability) and returns **numbers + caveats**.
  * For production randomness use the OS CSPRNG — ``os.urandom`` / ``secrets`` —
    NOT this module.

A clean assessment here is a *diagnostic signal*, never a certification and never
an authorization to derive keys from the sample.
"""

from __future__ import annotations

import json
import math
from collections import Counter
from dataclasses import asdict, dataclass
from typing import Any

from .errors import PqlensError

# Advisory heuristics (NOT a standard's pass/fail thresholds).
_MIN_USEFUL_SAMPLE = 256          # below this, too small to say much
_SUSPECT_SHANNON_BITS = 7.0       # for a full-entropy *byte* source expectation
_SUSPECT_MIN_ENTROPY_BITS = 5.0
_MCV_Z_99 = 2.5758293035489       # two-sided 99% normal quantile (SP 800-90B §6.3.1)


def binary_entropy(p: float) -> float:
    """Binary entropy function H(p) in bits. H(0)=H(1)=0, H(0.5)=1.

    A diagnostic for a single-bit sample (p = probability of a 1). This consumes
    a probability and returns a number; it produces no randomness.
    """
    if not 0.0 <= p <= 1.0:
        raise PqlensError(f"binary_entropy: p must be in [0, 1], got {p}")
    if p in (0.0, 1.0):
        return 0.0
    return -p * math.log2(p) - (1.0 - p) * math.log2(1.0 - p)


@dataclass(frozen=True)
class EntropyAssessment:
    sample_bytes: int
    distinct_values: int
    shannon_bits_per_byte: float
    min_entropy_bits_per_byte: float       # SP 800-90B §6.3.1 MCV estimate
    most_common_value: int
    most_common_fraction: float
    verdict: str                           # advisory: ok | suspect | insufficient-data
    caveats: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> EntropyAssessment:
        return cls(**{**d, "caveats": tuple(d["caveats"])})

    @classmethod
    def from_json(cls, s: str) -> EntropyAssessment:
        return cls.from_dict(json.loads(s))


def _shannon_bits_per_byte(counts: Counter[int], n: int) -> float:
    h = 0.0
    for c in counts.values():
        p = c / n
        h -= p * math.log2(p)
    return h


def _min_entropy_mcv(max_count: int, n: int) -> float:
    """SP 800-90B §6.3.1 Most-Common-Value min-entropy estimate (bits/byte).

    Uses the conservative 99% upper bound on the most-common-value probability,
    p_u = p_hat + Z * sqrt(p_hat(1-p_hat)/(n-1)), then H_inf = -log2(p_u). This
    deliberately *under*-estimates entropy (the safe direction).
    """
    p_hat = max_count / n
    if n > 1:
        p_u = p_hat + _MCV_Z_99 * math.sqrt(p_hat * (1.0 - p_hat) / (n - 1))
    else:
        p_u = 1.0
    p_u = min(1.0, p_u)
    return -math.log2(p_u) + 0.0  # +0.0 normalizes the -0.0 from log2(1.0)


def assess_entropy(sample: bytes) -> EntropyAssessment:
    """Assess the randomness of a **supplied** byte ``sample``.

    Returns an :class:`EntropyAssessment`. Does not generate, seed, or return any
    randomness. Raises :class:`PqlensError` on an empty sample.
    """
    if not isinstance(sample, (bytes, bytearray, memoryview)):
        raise PqlensError("assess_entropy: sample must be bytes-like")
    sample = bytes(sample)
    n = len(sample)
    if n == 0:
        raise PqlensError("assess_entropy: empty sample; supply captured bytes to measure")

    counts: Counter[int] = Counter(sample)
    max_value, max_count = counts.most_common(1)[0]
    shannon = _shannon_bits_per_byte(counts, n)
    min_entropy = _min_entropy_mcv(max_count, n)

    caveats: list[str] = [
        "Measurement only: this is NOT an SP 800-90B certification and NOT an "
        "authorization to derive keys from this sample. Use os.urandom/secrets "
        "for production randomness.",
        "Min-entropy is the SP 800-90B §6.3.1 Most-Common-Value estimate "
        f"(conservative 99% upper bound on p_max, Z={_MCV_Z_99:.3f}).",
        "Byte-level analysis only; it does not detect structure/correlation that "
        "a full SP 800-90B battery (e.g. collision, compression, predictors) would.",
    ]

    if n < _MIN_USEFUL_SAMPLE:
        verdict = "insufficient-data"
        caveats.append(
            f"Sample is {n} bytes (< {_MIN_USEFUL_SAMPLE}); estimates are unreliable."
        )
    elif shannon < _SUSPECT_SHANNON_BITS or min_entropy < _SUSPECT_MIN_ENTROPY_BITS:
        verdict = "suspect"
        caveats.append(
            "Advisory: entropy is below what a full-entropy byte source would "
            "show; investigate the source. (Heuristic thresholds, not a standard.)"
        )
    else:
        verdict = "ok"

    return EntropyAssessment(
        sample_bytes=n,
        distinct_values=len(counts),
        shannon_bits_per_byte=shannon,
        min_entropy_bits_per_byte=min_entropy,
        most_common_value=max_value,
        most_common_fraction=max_count / n,
        verdict=verdict,
        caveats=tuple(caveats),
    )
