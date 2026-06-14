"""Phase-6 acceptance tests for compliance evidence."""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from pqlens.backends import available_backends
from pqlens.compliance import (
    ComplianceReport,
    build_compliance_report,
    load_compliance_table,
    report_to_html,
    sign_report,
    verify_report,
)
from pqlens.discover import scan_path

FIXTURES = Path(__file__).parent / "fixtures"
HAVE_BACKEND = len(available_backends()) > 0


def _std(report: ComplianceReport, std: str):
    return next(a for a in report.standards if a.standard == std)


def _status_for(report: ComplianceReport, std: str, algorithm: str) -> str:
    findings = {f.algorithm: f.status for f in _std(report, std).findings}
    return findings[algorithm]


# --- mapping is data-driven + cited (acceptance #2) ------------------------ #
def test_verdicts_are_data_driven_not_hardcoded(monkeypatch):
    """Prove the verdict comes from data/compliance.json, not code: mutate the
    loaded table and the report must change accordingly. A hardcoded verdict
    would ignore the mutation."""
    import copy

    import pqlens.compliance as mod

    mutated = copy.deepcopy(mod.load_compliance_table())
    for rule in mutated["rules"]:
        if rule["match"].get("family") == "RSA":
            rule["assessments"]["CNSA-2.0"]["status"] = "compliant"  # flip it
    monkeypatch.setattr(mod, "load_compliance_table", lambda: mutated)

    report = build_compliance_report(FIXTURES)
    assert _status_for(report, "CNSA-2.0", "RSA") == "compliant"  # follows the DATA


def test_compliance_engine_reads_the_cited_data_file():
    """The engine sources its mapping from the cited data file."""
    import pqlens.compliance as mod

    assert "compliance.json" in inspect.getsource(mod)


def test_standards_carry_citations():
    table = load_compliance_table()
    for std_id, meta in table["standards"].items():
        assert meta["citation"], f"{std_id} missing citation"


# --- mapping correctness, exact + sourced (acceptance #3) ------------------ #
def test_rsa_and_mlkem_map_to_correct_status():
    inv = scan_path(FIXTURES)
    report = build_compliance_report(inv)
    # RSA is classical -> non-compliant under CNSA 2.0
    assert _status_for(report, "CNSA-2.0", "RSA") == "non-compliant"
    # ML-KEM-768 satisfies FIPS 203 ...
    assert _status_for(report, "FIPS-203", "ML-KEM-768") == "compliant"
    # ... but is below CNSA 2.0's mandated ML-KEM-1024 level
    assert _status_for(report, "CNSA-2.0", "ML-KEM-768") == "below-required-level"


def test_algorithm_specific_rule_beats_family_rule():
    """ML-KEM-1024 (algorithm rule) is CNSA-compliant; ML-KEM-768 (family) is not."""
    from pqlens.discover import Finding, Inventory

    inv = Inventory(
        root="synthetic", files_scanned=0, limitations=(),
        findings=(
            Finding("x", 1, "cryptokit", "MLKEM1024", "ML-KEM-1024", "pqc", "medium"),
            Finding("x", 2, "cryptokit", "MLKEM768", "ML-KEM-768", "pqc", "medium"),
        ),
    )
    report = build_compliance_report(inv)
    assert _status_for(report, "CNSA-2.0", "ML-KEM-1024") == "compliant"
    assert _status_for(report, "CNSA-2.0", "ML-KEM-768") == "below-required-level"


def test_eu_roadmap_is_advisory_not_binding():
    table = load_compliance_table()
    assert "advisory" in table["standards"]["EU-PQC-ROADMAP"]["citation"].lower() or \
        "not binding" in table["standards"]["EU-PQC-ROADMAP"]["citation"].lower()


# --- JSON round-trip (acceptance #1) --------------------------------------- #
def test_report_json_roundtrips_equal():
    report = build_compliance_report(FIXTURES)
    assert ComplianceReport.from_json(report.to_json()) == report


def test_unsigned_report_has_no_signature_and_fails_verify():
    report = build_compliance_report(FIXTURES)
    assert report.signature is None
    assert verify_report(report) is False  # unsigned => fail-closed


# --- signing is genuinely verifiable + fail-closed (acceptance #4) --------- #
@pytest.mark.skipif(not HAVE_BACKEND, reason="no audited signature backend")
def test_sign_then_verify_true():
    report = sign_report(build_compliance_report(FIXTURES))
    assert report.signature is not None
    assert report.signature.scheme.startswith("hybrid:ML-DSA-65")
    assert "ephemeral" in report.signature.caveat.lower()
    assert verify_report(report) is True


@pytest.mark.skipif(not HAVE_BACKEND, reason="no audited signature backend")
def test_tampering_breaks_signature():
    from dataclasses import replace

    report = sign_report(build_compliance_report(FIXTURES))
    assert verify_report(report) is True
    # Tamper with the body (target) but keep the old signature -> must fail.
    tampered = replace(report, target=report.target + "/EVIL")
    assert verify_report(tampered) is False


@pytest.mark.skipif(not HAVE_BACKEND, reason="no audited signature backend")
def test_roundtrip_preserves_verifiable_signature():
    report = sign_report(build_compliance_report(FIXTURES))
    again = ComplianceReport.from_json(report.to_json())
    assert verify_report(again) is True


# --- HTML evidence pack (acceptance #5) ------------------------------------ #
def test_html_export_embeds_signature_when_signed():
    unsigned = build_compliance_report(FIXTURES)
    assert "UNSIGNED DRAFT" in report_to_html(unsigned)
    if HAVE_BACKEND:
        signed = sign_report(unsigned)
        html = report_to_html(signed)
        assert "Signature" in html
        assert signed.signature.signed_sha256 in html


def test_html_is_self_contained():
    html = report_to_html(build_compliance_report(FIXTURES))
    assert html.startswith("<!doctype html>")
    assert "CNSA-2.0" in html  # standards rendered
