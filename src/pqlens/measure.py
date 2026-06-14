"""Migration cost / overhead measurement core.

Produces a typed, JSON-round-trippable :class:`MigrationCostReport` so a team can
**price** a PQC migration before doing it: size deltas, handshake bytes-on-wire,
benchmarked timings (warmup + variance), and a clearly-labeled energy model.

Honesty rules this module holds (guardrails #4, #5):
  * Every size traces to a citation (the versioned ``data/algorithms.json``) and,
    where possible, is **confirmed by a live roundtrip** before it is reported.
  * The OpenSSL backend is a *CLI subprocess*, so its timings include
    process-spawn overhead — they measure "OpenSSL CLI", not "ML-KEM in a hot
    library". We quantify that floor (`subprocess_overhead_ms`) and headline the
    **exact size deltas** over the caveated timings.
  * The energy figure is an explicit *model*: absolute nanojoules are
    `estimated=True` (constant-dependent); the ratio to baseline is exact.
"""

from __future__ import annotations

import hmac
import json
import statistics
import subprocess
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from importlib import resources
from typing import Any

from . import __version__
from .backends import get_kem_backend
from .backends.base import KEMBackend
from .baselines import x25519_keygen, x25519_sizes
from .errors import PqlensError

# Illustrative order-of-magnitude radio/network transmit energy. This is a MODEL
# PARAMETER, not a measured constant for the user's environment — hence every
# absolute energy figure is flagged estimated=True and this value is overridable.
DEFAULT_NJ_PER_BYTE = 10.0


# --------------------------------------------------------------------------- #
# Report dataclasses (all frozen, all JSON-serializable)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Timing:
    operation: str
    iterations: int
    mean_ms: float
    median_ms: float
    stdev_ms: float
    min_ms: float


@dataclass(frozen=True)
class EnergyEstimate:
    estimated: bool
    transmit_nanojoules: float
    relative_to_baseline: float
    nj_per_byte: float
    model: str
    assumptions: tuple[str, ...]
    sources: tuple[str, ...]


@dataclass(frozen=True)
class AlgorithmCost:
    algorithm: str
    kind: str
    quantum_secure: bool
    public_key_bytes: int
    ciphertext_bytes: int
    shared_secret_bytes: int
    secret_key_bytes: int | None
    handshake_wire_bytes: int
    handshake_delta_bytes: int
    handshake_multiplier: float
    live_verified: bool
    size_sources: tuple[str, ...]
    timings: tuple[Timing, ...]
    energy: EnergyEstimate
    notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class MigrationCostReport:
    generated_by: str
    baseline: str
    baseline_wire_bytes: int
    iterations: int
    backend: str | None
    subprocess_overhead_ms: float | None
    backend_overhead_note: str
    algorithms: tuple[AlgorithmCost, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> MigrationCostReport:
        algos = tuple(
            AlgorithmCost(
                **{
                    **a,
                    "size_sources": tuple(a["size_sources"]),
                    "notes": tuple(a.get("notes", ())),
                    "timings": tuple(Timing(**t) for t in a["timings"]),
                    "energy": EnergyEstimate(
                        **{
                            **a["energy"],
                            "assumptions": tuple(a["energy"]["assumptions"]),
                            "sources": tuple(a["energy"]["sources"]),
                        }
                    ),
                }
            )
            for a in d["algorithms"]
        )
        return cls(
            generated_by=d["generated_by"],
            baseline=d["baseline"],
            baseline_wire_bytes=d["baseline_wire_bytes"],
            iterations=d["iterations"],
            backend=d["backend"],
            subprocess_overhead_ms=d["subprocess_overhead_ms"],
            backend_overhead_note=d["backend_overhead_note"],
            algorithms=algos,
        )

    @classmethod
    def from_json(cls, s: str) -> MigrationCostReport:
        return cls.from_dict(json.loads(s))


# --------------------------------------------------------------------------- #
# Data table
# --------------------------------------------------------------------------- #
def load_algorithm_table() -> dict[str, Any]:
    """Load the versioned, cited size table that ships inside the package."""
    raw = resources.files("pqlens.data").joinpath("algorithms.json").read_text("utf-8")
    return json.loads(raw)


# --------------------------------------------------------------------------- #
# Benchmark helper (warmup + variance)
# --------------------------------------------------------------------------- #
def _bench(operation: str, fn: Callable[[], object], *, iterations: int, warmup: int) -> Timing:
    for _ in range(max(0, warmup)):
        fn()
    samples_ms: list[float] = []
    for _ in range(iterations):
        t0 = time.perf_counter_ns()
        fn()
        samples_ms.append((time.perf_counter_ns() - t0) / 1e6)
    return Timing(
        operation=operation,
        iterations=iterations,
        mean_ms=statistics.fmean(samples_ms),
        median_ms=statistics.median(samples_ms),
        stdev_ms=statistics.stdev(samples_ms) if len(samples_ms) > 1 else 0.0,
        min_ms=min(samples_ms),
    )


def _subprocess_overhead_ms(backend: KEMBackend, *, iterations: int, warmup: int) -> float | None:
    """Quantify per-call process-spawn cost for a CLI backend (a no-op crypto op).

    For the OpenSSL backend this times ``openssl version`` — the floor below
    which no measured ML-KEM timing can go, because every op spawns a process.
    Returns None for in-process backends.
    """
    if backend.name != "openssl":
        return None
    from .backends.openssl import _openssl_path  # local import: private helper

    exe = _openssl_path()
    if not exe:
        return None

    def _noop() -> None:
        subprocess.run([exe, "version"], capture_output=True, check=False)

    return _bench("subprocess-spawn", _noop, iterations=iterations, warmup=warmup).mean_ms


# --------------------------------------------------------------------------- #
# Energy model
# --------------------------------------------------------------------------- #
def _energy(wire_bytes: int, baseline_wire_bytes: int, nj_per_byte: float) -> EnergyEstimate:
    return EnergyEstimate(
        estimated=True,
        transmit_nanojoules=wire_bytes * nj_per_byte,
        relative_to_baseline=(wire_bytes / baseline_wire_bytes) if baseline_wire_bytes else 0.0,
        nj_per_byte=nj_per_byte,
        model="transmit_energy = handshake_wire_bytes * nj_per_byte",
        assumptions=(
            f"nj_per_byte={nj_per_byte} is an ILLUSTRATIVE order-of-magnitude "
            "transmit-energy parameter, not measured for your hardware; override it.",
            "Counts handshake key-material bytes only (one ephemeral exchange); "
            "excludes framing, retransmits, and compute energy.",
        ),
        sources=(
            "Energy scales linearly with bytes transmitted; the RATIO to baseline "
            "is exact and constant-independent. Absolute nJ is a model estimate.",
        ),
    )


# --------------------------------------------------------------------------- #
# Public entrypoint
# --------------------------------------------------------------------------- #
def measure_migration_cost(
    algorithms: list[str] | tuple[str, ...] = ("ML-KEM-768",),
    *,
    baseline: str = "X25519",
    iterations: int = 10,
    warmup: int = 2,
    nj_per_byte: float = DEFAULT_NJ_PER_BYTE,
    backend: KEMBackend | None = None,
) -> MigrationCostReport:
    """Measure migration cost for ``algorithms`` against an X25519 baseline.

    Sizes come from the cited table and, when ``live_verifiable``, are confirmed
    by a real roundtrip through an audited backend. Timings use warmup + N
    iterations and report variance. The energy figure is an explicit model.
    """
    table = load_algorithm_table()
    entries = table["algorithms"]
    if baseline not in entries:
        raise PqlensError(f"unknown baseline {baseline!r}")
    baseline_wire = entries[baseline]["public_key_bytes"] + entries[baseline]["ciphertext_bytes"]

    # Resolve a KEM backend lazily; sizes still report if none is available.
    resolved_backend: KEMBackend | None = backend
    if resolved_backend is None:
        try:
            resolved_backend = get_kem_backend()
        except PqlensError:
            resolved_backend = None

    overhead = (
        _subprocess_overhead_ms(resolved_backend, iterations=max(3, iterations), warmup=warmup)
        if resolved_backend is not None
        else None
    )

    costs: list[AlgorithmCost] = []
    for name in algorithms:
        if name not in entries:
            raise PqlensError(
                f"unknown algorithm {name!r}; known: {', '.join(sorted(entries))}"
            )
        e = entries[name]
        if "ciphertext_bytes" not in e:
            raise PqlensError(
                f"{name!r} is a {e.get('kind', 'non-KEM')} entry, not a measurable "
                "KEM; the cost model handles key establishment (handshake), not "
                "signatures. Use pqlens.discover to inventory signature algorithms."
            )
        pk, ct = e["public_key_bytes"], e["ciphertext_bytes"]
        wire = pk + ct
        notes: list[str] = []

        live_verified, timings = _measure_one(
            name, e, resolved_backend, iterations=iterations, warmup=warmup, notes=notes
        )

        costs.append(
            AlgorithmCost(
                algorithm=name,
                kind=e["kind"],
                quantum_secure=e["quantum_secure"],
                public_key_bytes=pk,
                ciphertext_bytes=ct,
                shared_secret_bytes=e["shared_secret_bytes"],
                secret_key_bytes=e.get("secret_key_bytes"),
                handshake_wire_bytes=wire,
                handshake_delta_bytes=wire - baseline_wire,
                handshake_multiplier=round(wire / baseline_wire, 4) if baseline_wire else 0.0,
                live_verified=live_verified,
                size_sources=tuple(e["sources"]),
                timings=tuple(timings),
                energy=_energy(wire, baseline_wire, nj_per_byte),
                notes=tuple(notes),
            )
        )

    return MigrationCostReport(
        generated_by=f"pqlens {__version__}",
        baseline=baseline,
        baseline_wire_bytes=baseline_wire,
        iterations=iterations,
        backend=resolved_backend.name if resolved_backend else None,
        subprocess_overhead_ms=overhead,
        backend_overhead_note=(
            "Timings via the OpenSSL CLI backend include per-call process-spawn "
            "overhead (see subprocess_overhead_ms); they reflect 'OpenSSL CLI', "
            "not 'ML-KEM in a hot in-process library'. Treat the exact size "
            "deltas as the primary migration-cost signal; an in-process liboqs "
            "backend would give library-level timings."
            if resolved_backend and resolved_backend.name == "openssl"
            else "No CLI subprocess overhead applies to this backend."
        ),
        algorithms=tuple(costs),
    )


def _measure_one(
    name: str,
    entry: dict[str, Any],
    backend: KEMBackend | None,
    *,
    iterations: int,
    warmup: int,
    notes: list[str],
) -> tuple[bool, list[Timing]]:
    """Live-verify sizes and benchmark one algorithm; returns (live_verified, timings)."""
    # X25519 baseline: time in-process via cryptography; sizes are RFC-fixed.
    if name == "X25519":
        sizes = x25519_sizes()
        keygen_t = _bench("keygen", x25519_keygen, iterations=iterations, warmup=warmup)
        notes.append("Timed in-process via pyca/cryptography (no subprocess overhead).")
        # Confirm the live shared-secret length matches the table.
        secret_len = len(x25519_keygen().exchange(x25519_keygen().public_key()))
        return secret_len == sizes.shared_secret_bytes, [keygen_t]

    # Algorithms without a live backend (e.g. X-Wing here): sizes only, cited.
    if not entry.get("live_verifiable") or backend is None:
        notes.append(
            "Sizes are cited only (no available backend live-verifies this "
            "algorithm in this environment); timings omitted."
        )
        return False, []

    if name not in backend.supported_algorithms():
        notes.append(f"Backend {backend.name!r} does not run {name}; sizes cited only.")
        return False, []

    # Live roundtrip: confirm sizes == table AND the KEM actually recovered the
    # secret (constant-time compare — guardrail #3). live_verified therefore
    # means "a correct roundtrip whose sizes match the cited table", not merely
    # "the byte counts happen to line up".
    keypair = backend.keygen(name)
    enc = backend.encapsulate(name, keypair.public_key)
    recovered = backend.decapsulate(name, keypair.secret_key, enc.ciphertext)
    sizes_ok = (
        len(enc.ciphertext) == entry["ciphertext_bytes"]
        and len(enc.shared_secret) == entry["shared_secret_bytes"]
        and len(recovered) == entry["shared_secret_bytes"]
    )
    secret_ok = hmac.compare_digest(enc.shared_secret, recovered)
    live_ok = sizes_ok and secret_ok
    if not sizes_ok:
        notes.append(
            f"LIVE/TABLE SIZE MISMATCH: measured ct={len(enc.ciphertext)} "
            f"ss={len(enc.shared_secret)} vs table ct={entry['ciphertext_bytes']} "
            f"ss={entry['shared_secret_bytes']}."
        )
    if not secret_ok:
        notes.append("LIVE ROUNDTRIP FAILED: decapsulated secret != encapsulated secret.")

    timings = [
        _bench("keygen", lambda: backend.keygen(name), iterations=iterations, warmup=warmup),
        _bench(
            "encapsulate",
            lambda: backend.encapsulate(name, keypair.public_key),
            iterations=iterations,
            warmup=warmup,
        ),
        _bench(
            "decapsulate",
            lambda: backend.decapsulate(name, keypair.secret_key, enc.ciphertext),
            iterations=iterations,
            warmup=warmup,
        ),
    ]
    return live_ok, timings
