"""Phase-2 acceptance tests for the migration-cost measurement core."""

from __future__ import annotations

import pytest

from pqlens.backends import available_backends
from pqlens.errors import PqlensError
from pqlens.measure import (
    MigrationCostReport,
    load_algorithm_table,
    measure_migration_cost,
)

HAVE_BACKEND = len(available_backends()) > 0
FAST = {"iterations": 5, "warmup": 1}


# --- the cited table itself ------------------------------------------------ #
def test_table_matches_fips203_ml_kem_768():
    """Acceptance #2 (static half): table agrees with FIPS 203 for ML-KEM-768."""
    e = load_algorithm_table()["algorithms"]["ML-KEM-768"]
    assert e["public_key_bytes"] == 1184
    assert e["ciphertext_bytes"] == 1088
    assert e["shared_secret_bytes"] == 32
    assert e["secret_key_bytes"] == 2400
    # Provenance is recorded (FIPS + CryptoKit + live OpenSSL) — guardrail #5.
    assert any("FIPS 203" in s for s in e["sources"])
    assert any("CryptoKit" in s for s in e["sources"])


def test_every_table_entry_has_sources():
    for name, e in load_algorithm_table()["algorithms"].items():
        assert e["sources"], f"{name} has no citation"


# --- report shape / JSON round-trip --------------------------------------- #
@pytest.mark.skipif(not HAVE_BACKEND, reason="no audited KEM backend")
def test_report_json_roundtrips_equal():
    """Acceptance #1: frozen dataclass; to_json()/from_json() round-trip equal."""
    report = measure_migration_cost(["ML-KEM-768"], **FAST)
    again = MigrationCostReport.from_json(report.to_json())
    assert again == report


@pytest.mark.skipif(not HAVE_BACKEND, reason="no audited KEM backend")
def test_live_verification_confirms_sizes():
    """Acceptance #2 (live half): a real roundtrip confirms ct+ss == table."""
    report = measure_migration_cost(["ML-KEM-768"], **FAST)
    (a,) = report.algorithms
    assert a.live_verified is True
    assert a.ciphertext_bytes == 1088
    assert a.shared_secret_bytes == 32


def test_handshake_delta_positive_and_monotonic():
    """Acceptance #3: PQC delta > 0; monotonic 1024 > 768 > 512.

    Pure size arithmetic — runs without a backend (timings just omitted)."""
    algos = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]
    report = measure_migration_cost(algos, **FAST)
    by = {a.algorithm: a for a in report.algorithms}
    for name in algos:
        assert by[name].handshake_delta_bytes > 0
        assert by[name].handshake_multiplier > 1.0
    assert (
        by["ML-KEM-1024"].handshake_delta_bytes
        > by["ML-KEM-768"].handshake_delta_bytes
        > by["ML-KEM-512"].handshake_delta_bytes
    )


@pytest.mark.skipif(not HAVE_BACKEND, reason="no audited KEM backend")
def test_benchmarks_have_variance_stats():
    """Acceptance #4: each timing has mean/median/stdev/min, n>=5, stdev>=0."""
    report = measure_migration_cost(["ML-KEM-768"], iterations=5, warmup=1)
    (a,) = report.algorithms
    ops = {t.operation for t in a.timings}
    assert ops == {"keygen", "encapsulate", "decapsulate"}
    for t in a.timings:
        assert t.iterations >= 5
        assert t.stdev_ms >= 0.0
        assert t.min_ms <= t.mean_ms
        assert t.median_ms >= 0.0


def test_energy_is_flagged_estimated_with_provenance():
    """Acceptance #5: energy carries estimated=True + non-empty assumptions/sources."""
    report = measure_migration_cost(["ML-KEM-768"], **FAST)
    (a,) = report.algorithms
    assert a.energy.estimated is True
    assert a.energy.assumptions
    assert a.energy.sources
    # The ratio is exact even though the absolute nJ is a model estimate.
    assert a.energy.relative_to_baseline == pytest.approx(
        a.handshake_wire_bytes / report.baseline_wire_bytes
    )


# --- honesty about the CLI subprocess overhead ---------------------------- #
@pytest.mark.skipif(not HAVE_BACKEND, reason="no audited KEM backend")
def test_subprocess_overhead_is_quantified_for_openssl():
    report = measure_migration_cost(["ML-KEM-768"], **FAST)
    if report.backend == "openssl":
        assert report.subprocess_overhead_ms is not None
        assert report.subprocess_overhead_ms >= 0.0
        assert "CLI" in report.backend_overhead_note


def test_cited_only_algorithm_reports_sizes_without_timings():
    """X-Wing has no live backend here: sizes are cited, timings omitted, flagged."""
    report = measure_migration_cost(["X-Wing"], **FAST)
    (a,) = report.algorithms
    assert a.kind == "hybrid-kem"
    assert a.quantum_secure is True
    assert a.public_key_bytes == 1216
    assert a.ciphertext_bytes == 1120
    assert a.live_verified is False
    assert a.timings == ()
    assert any("cited only" in n for n in a.notes)


# --- error paths ----------------------------------------------------------- #
def test_measure_x25519_baseline_against_itself():
    """Measuring the baseline itself: delta 0, multiplier 1, timed in-process."""
    report = measure_migration_cost(["X25519"], **FAST)
    (a,) = report.algorithms
    assert a.quantum_secure is False
    assert a.handshake_delta_bytes == 0
    assert a.handshake_multiplier == 1.0
    assert a.live_verified is True  # in-process exchange confirms 32-byte secret
    assert {t.operation for t in a.timings} == {"keygen"}
    assert any("in-process" in n for n in a.notes)


def test_unknown_algorithm_raises():
    with pytest.raises(PqlensError, match="unknown algorithm"):
        measure_migration_cost(["RSA-2048"], **FAST)


def test_unknown_baseline_raises():
    with pytest.raises(PqlensError, match="unknown baseline"):
        measure_migration_cost(["ML-KEM-768"], baseline="NOPE", **FAST)


def test_signature_algorithm_is_not_measurable():
    """ML-DSA is in the table (for discovery) but is a signature, not a KEM —
    the cost model must refuse it with a clear message, not crash."""
    with pytest.raises(PqlensError, match="not a measurable"):
        measure_migration_cost(["ML-DSA-65"], **FAST)
