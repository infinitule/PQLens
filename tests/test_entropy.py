"""Phase-5 acceptance tests for entropy diagnostics (measurement only)."""

from __future__ import annotations

import inspect
import os

import pytest

import pqlens.entropy as entropy_mod
from pqlens.entropy import EntropyAssessment, assess_entropy, binary_entropy
from pqlens.errors import PqlensError


# --- binary entropy H(p) (acceptance #2) ----------------------------------- #
def test_binary_entropy_endpoints_and_midpoint():
    assert binary_entropy(0.0) == 0.0
    assert binary_entropy(1.0) == 0.0
    assert binary_entropy(0.5) == pytest.approx(1.0)
    assert binary_entropy(0.11) == pytest.approx(0.4999, abs=1e-3)


def test_binary_entropy_rejects_out_of_range():
    with pytest.raises(PqlensError):
        binary_entropy(1.5)
    with pytest.raises(PqlensError):
        binary_entropy(-0.1)


# --- degenerate + healthy samples (acceptance #3, #4) ---------------------- #
def test_all_identical_bytes_has_near_zero_entropy():
    a = assess_entropy(b"\x00" * 4096)
    assert a.shannon_bits_per_byte == pytest.approx(0.0)
    assert a.min_entropy_bits_per_byte == pytest.approx(0.0, abs=1e-6)
    assert a.distinct_values == 1
    assert a.most_common_fraction == 1.0
    assert a.verdict == "suspect"


def test_urandom_sample_looks_high_entropy():
    # The RANDOMNESS IS GENERATED IN THE TEST, never by pqlens (guardrail #2).
    a = assess_entropy(os.urandom(65536))
    assert a.shannon_bits_per_byte > 7.9           # near the 8.0 max
    assert a.min_entropy_bits_per_byte > 6.0        # meaningfully positive
    assert a.verdict == "ok"


# --- min-entropy catches bias the average hides (acceptance #5) ------------ #
def test_biased_sample_min_entropy_below_shannon():
    sample = b"\x00" * 9000 + os.urandom(1000)  # ~90% one value
    a = assess_entropy(sample)
    assert a.min_entropy_bits_per_byte < a.shannon_bits_per_byte
    assert a.most_common_value == 0
    assert a.most_common_fraction == pytest.approx(0.9, abs=0.02)


def test_small_sample_is_flagged_insufficient():
    a = assess_entropy(os.urandom(16))
    assert a.verdict == "insufficient-data"
    assert any("bytes" in c for c in a.caveats)


# --- errors ---------------------------------------------------------------- #
def test_empty_sample_raises():
    with pytest.raises(PqlensError, match="empty sample"):
        assess_entropy(b"")


def test_non_bytes_rejected():
    with pytest.raises(PqlensError, match="bytes-like"):
        assess_entropy("not bytes")  # type: ignore[arg-type]


# --- JSON round-trip (acceptance #1) --------------------------------------- #
def test_assessment_json_roundtrips_equal():
    a = assess_entropy(os.urandom(2048))
    assert EntropyAssessment.from_json(a.to_json()) == a


# --- guardrail #2 enforced by test (acceptance #6) ------------------------- #
def test_module_exposes_no_randomness_generating_callable():
    """The entropy module must not be usable as an RNG. No public callable may be
    named like a generator/seeder, and the module must not import an RNG."""
    forbidden_prefixes = ("generate", "seed", "random", "rng", "urandom", "prng",
                          "drbg", "keygen", "sample_bytes", "make")
    for name in vars(entropy_mod):
        if name.startswith("_"):
            continue
        assert not any(name.lower().startswith(p) for p in forbidden_prefixes), (
            f"entropy module exposes suspicious name {name!r} (guardrail #2)"
        )

    # No RNG modules imported into entropy's namespace.
    for rng in ("os", "secrets", "random"):
        assert not hasattr(entropy_mod, rng), f"entropy must not import {rng} (guardrail #2)"

    # Every public callable's return is an assessment/number, never bytes.
    a = assess_entropy(b"\x01\x02\x03\x04" * 100)
    assert isinstance(a, EntropyAssessment)
    assert isinstance(binary_entropy(0.3), float)


def test_source_has_no_rng_imports():
    """Parse the module's actual import statements (not docstring text)."""
    import ast

    tree = ast.parse(inspect.getsource(entropy_mod))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert {"os", "secrets", "random"}.isdisjoint(imported), (
        f"entropy must not import an RNG; imported: {sorted(imported)}"
    )
