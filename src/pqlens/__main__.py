"""Minimal CLI for pqlens.

Phase 1 ships only what the smoke test needs: ``--selftest`` (one ML-KEM
roundtrip through an audited backend) and ``--backends`` (honest report of what
is available). Richer commands arrive in later phases.
"""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .backends import available_backends
from .compliance import build_compliance_report, report_to_html, sign_report, verify_report
from .discover import scan_path
from .entropy import assess_entropy
from .errors import PqlensError
from .hybrid import hybrid_kem_selftest, hybrid_sig_selftest
from .kem import kem_roundtrip_selftest
from .measure import measure_migration_cost


def _print_report(report) -> None:  # noqa: ANN001 - MigrationCostReport
    print(f"# {report.generated_by} — migration cost vs {report.baseline} "
          f"({report.baseline_wire_bytes} B handshake)")
    if report.subprocess_overhead_ms is not None:
        print(f"# backend={report.backend}  subprocess_overhead≈"
              f"{report.subprocess_overhead_ms:.2f} ms/call")
    print(f"# {report.backend_overhead_note}")
    for a in report.algorithms:
        print(f"\n## {a.algorithm}  [{a.kind}, "
              f"{'quantum-secure' if a.quantum_secure else 'CLASSICAL'}]")
        print(f"  sizes: pk={a.public_key_bytes}B ct={a.ciphertext_bytes}B "
              f"ss={a.shared_secret_bytes}B")
        print(f"  handshake: {a.handshake_wire_bytes}B on wire  "
              f"(+{a.handshake_delta_bytes}B, {a.handshake_multiplier}x baseline)")
        print(f"  energy: {a.energy.relative_to_baseline:.2f}x baseline transmit "
              f"(absolute nJ estimated={a.energy.estimated})")
        print(f"  live_verified={a.live_verified}")
        for t in a.timings:
            print(f"  bench {t.operation:<12} mean={t.mean_ms:.3f}ms "
                  f"median={t.median_ms:.3f}ms stdev={t.stdev_ms:.3f}ms "
                  f"min={t.min_ms:.3f}ms (n={t.iterations})")
        for note in a.notes:
            print(f"  note: {note}")


def _print_compliance(report) -> None:  # noqa: ANN001 - ComplianceReport
    print(f"# {report.generated_by} — compliance evidence for {report.target}")
    print(f"# algorithms assessed: {report.summary['algorithms_assessed']}")
    for a in report.standards:
        print(f"\n## {a.standard} [{a.status}] — {a.title}")
        print(f"   cite: {a.citation}")
        for f in a.findings:
            print(f"   - {f.algorithm:<14} {f.status:<22} {f.rationale}")
    if report.signature is not None:
        print(f"\n# signed: {report.signature.scheme}  "
              f"sha256={report.signature.signed_sha256[:16]}…")
        print(f"# {report.signature.caveat}")
    else:
        print("\n# UNSIGNED DRAFT (use --sign to cryptographically sign)")
    print("# caveats:")
    for c in report.caveats:
        print(f"  - {c}")


def _print_entropy(a) -> None:  # noqa: ANN001 - EntropyAssessment
    print(f"# pqlens entropy assessment — {a.sample_bytes} bytes, "
          f"{a.distinct_values}/256 distinct values")
    print(f"  verdict: {a.verdict}")
    print(f"  shannon:     {a.shannon_bits_per_byte:.4f} bits/byte (max 8)")
    print(f"  min-entropy: {a.min_entropy_bits_per_byte:.4f} bits/byte (SP 800-90B MCV)")
    print(f"  most-common value 0x{a.most_common_value:02x} = "
          f"{a.most_common_fraction * 100:.2f}% of sample")
    print("# caveats:")
    for c in a.caveats:
        print(f"  - {c}")


def _print_inventory(inv) -> None:  # noqa: ANN001 - Inventory
    print(f"# pqlens scan of {inv.root} — {inv.files_scanned} files, "
          f"{len(inv.findings)} findings")
    counts = inv.counts_by_risk()
    if counts:
        print("# risk: " + "  ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    for f in inv.findings:
        loc = f"{f.path}:{f.line}" if f.line else f.path
        algo = f.algorithm or "?"
        print(f"  [{f.risk:<18}] {algo:<14} {f.detail:<24} "
              f"({f.scanner}, {f.confidence}) {loc}")
    print("# limitations:")
    for lim in inv.limitations:
        print(f"  - {lim}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pqlens",
        description="A lens on your post-quantum migration (measurement, not crypto).",
    )
    parser.add_argument("--version", action="version", version=f"pqlens {__version__}")
    parser.add_argument(
        "--selftest",
        action="store_true",
        help="run one ML-KEM-768 encap/decap through an audited backend",
    )
    parser.add_argument(
        "--algorithm",
        default="ML-KEM-768",
        help="KEM algorithm for --selftest (default: ML-KEM-768)",
    )
    parser.add_argument(
        "--backends",
        action="store_true",
        help="list audited KEM backends available in this environment",
    )
    parser.add_argument(
        "--measure",
        action="store_true",
        help="measure migration cost (sizes, handshake delta, benchmarks, energy)",
    )
    parser.add_argument(
        "--algorithms",
        default="ML-KEM-768",
        help="comma-separated algorithms for --measure (default: ML-KEM-768)",
    )
    parser.add_argument(
        "--iterations", type=int, default=10, help="benchmark iterations for --measure"
    )
    parser.add_argument(
        "--json", action="store_true", help="emit --measure/--scan/--entropy output as JSON"
    )
    parser.add_argument(
        "--scan",
        metavar="PATH",
        help="inventory crypto usage under PATH, tagged by quantum risk",
    )
    parser.add_argument(
        "--hybrid-selftest",
        action="store_true",
        help="run hybrid KEM (ML-KEM+X25519) and hybrid sig (ML-DSA+Ed25519) round-trips",
    )
    parser.add_argument(
        "--entropy",
        metavar="FILE",
        help="measure the entropy of a CAPTURED byte sample file (never generates one)",
    )
    parser.add_argument(
        "--compliance",
        metavar="PATH",
        help="build a standards-compliance evidence report for crypto under PATH",
    )
    parser.add_argument(
        "--sign", action="store_true",
        help="cryptographically sign the --compliance report (hybrid ML-DSA+Ed25519)",
    )
    parser.add_argument(
        "--html", metavar="FILE", help="write the --compliance report as HTML to FILE",
    )
    args = parser.parse_args(argv)

    if args.compliance:
        report = build_compliance_report(args.compliance)
        if args.sign:
            report = sign_report(report)
        if args.html:
            with open(args.html, "w", encoding="utf-8") as fh:
                fh.write(report_to_html(report))
        if args.json:
            print(report.to_json())
        else:
            _print_compliance(report)
        if args.sign:
            print(f"# signature verifies: {verify_report(report)}")
        return 0

    if args.entropy:
        try:
            with open(args.entropy, "rb") as fh:
                sample = fh.read()
            assessment = assess_entropy(sample)
        except OSError as exc:
            print(f"ENTROPY ERROR: {exc}", file=sys.stderr)
            return 2
        except PqlensError as exc:
            print(f"ENTROPY ERROR: {exc}", file=sys.stderr)
            return 2
        if args.json:
            print(assessment.to_json())
        else:
            _print_entropy(assessment)
        return 0

    if args.hybrid_selftest:
        try:
            kem_ok = hybrid_kem_selftest()
            sig_ok = hybrid_sig_selftest()
        except PqlensError as exc:
            print(f"HYBRID SELFTEST ERROR: {exc}", file=sys.stderr)
            return 2
        ok = kem_ok and sig_ok
        print(f"{'PASS' if ok else 'FAIL'} hybrid KEM(ML-KEM-768+X25519)={kem_ok} "
              f"hybrid SIG(ML-DSA-65+Ed25519)={sig_ok}")
        return 0 if ok else 1

    if args.scan:
        inv = scan_path(args.scan)
        if args.json:
            print(inv.to_json())
        else:
            _print_inventory(inv)
        return 0

    if args.measure:
        algos = [a.strip() for a in args.algorithms.split(",") if a.strip()]
        try:
            report = measure_migration_cost(algos, iterations=args.iterations)
        except PqlensError as exc:
            print(f"MEASURE ERROR: {exc}", file=sys.stderr)
            return 2
        if args.json:
            print(report.to_json())
        else:
            _print_report(report)
        return 0

    if args.backends:
        avail = available_backends()
        if not avail:
            print("no audited KEM backend available", file=sys.stderr)
            return 1
        for b in avail:
            print(f"{b.name}: {', '.join(b.supported_algorithms())}")
        return 0

    if args.selftest:
        try:
            r = kem_roundtrip_selftest(args.algorithm)
        except PqlensError as exc:
            print(f"SELFTEST ERROR: {exc}", file=sys.stderr)
            return 2
        except AssertionError as exc:
            print(f"SELFTEST FAIL: {exc}", file=sys.stderr)
            return 1
        print(
            f"PASS {r.algorithm} via {r.backend}: "
            f"shared_secret={r.shared_secret_len}B ciphertext={r.ciphertext_len}B "
            f"match={r.secrets_match}"
        )
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
