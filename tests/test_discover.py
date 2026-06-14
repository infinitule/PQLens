"""Phase-3 acceptance tests for crypto-agility discovery."""

from __future__ import annotations

import datetime
from pathlib import Path

from pqlens.discover import (
    HYBRID_READY,
    PQC,
    QUANTUM_VULNERABLE,
    UNKNOWN,
    Inventory,
    classify,
    scan_path,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _pairs(inv: Inventory) -> set[tuple[str | None, str]]:
    return {(f.algorithm, f.risk) for f in inv.findings}


# --- classification derives from the cited table (acceptance #6) ----------- #
def test_classify_pqc_and_hybrid_come_from_table():
    assert classify("ML-KEM-768") == PQC
    assert classify("ML-DSA-65") == PQC          # added to table this phase
    assert classify("X-Wing") == HYBRID_READY
    assert classify("X25519") == QUANTUM_VULNERABLE   # in table, quantum_secure=false
    assert classify("RSA") == QUANTUM_VULNERABLE      # classical map
    assert classify("Frobnicate-512") == UNKNOWN


# --- Python AST scanner (acceptance #3) ------------------------------------ #
def test_python_ast_finds_classical_usage():
    inv = scan_path(FIXTURES / "python_app.py")
    pairs = _pairs(inv)
    assert ("RSA", QUANTUM_VULNERABLE) in pairs
    assert ("ECDSA-P256", QUANTUM_VULNERABLE) in pairs
    assert ("X25519", QUANTUM_VULNERABLE) in pairs
    # AST findings are parsed => high confidence, and never executed.
    assert all(f.confidence == "high" for f in inv.findings if f.scanner == "python-ast")


# --- certificate scanner (acceptance #4) ----------------------------------- #
def test_certificate_scanner_reads_rsa_pem(tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pqlens-test")])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    pem = tmp_path / "server.pem"
    pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    inv = scan_path(pem)
    (f,) = [x for x in inv.findings if x.scanner == "certificate"]
    assert f.detail == "RSA/2048"
    assert f.algorithm == "RSA"
    assert f.risk == QUANTUM_VULNERABLE
    assert f.confidence == "high"


# --- CryptoKit token scanner (acceptance #5) ------------------------------- #
def test_cryptokit_scanner_tags_hybrid_and_classical():
    inv = scan_path(FIXTURES / "cryptokit_snippet.swift")
    pairs = _pairs(inv)
    assert ("X-Wing", HYBRID_READY) in pairs
    assert ("ML-KEM-768", PQC) in pairs
    assert ("ML-DSA-65", PQC) in pairs
    assert ("ECDSA-P256", QUANTUM_VULNERABLE) in pairs


# --- TLS + JWT scanners ---------------------------------------------------- #
def test_tls_config_scanner():
    inv = scan_path(FIXTURES / "nginx.conf")
    pairs = _pairs(inv)
    assert ("ECDHE", QUANTUM_VULNERABLE) in pairs
    assert ("DHE", QUANTUM_VULNERABLE) in pairs
    assert ("X-Wing", HYBRID_READY) in pairs        # X25519MLKEM768 group
    assert ("X25519", QUANTUM_VULNERABLE) in pairs
    # word-boundary matching: ECDH should NOT be reported from inside "ECDHE"
    assert ("ECDH", QUANTUM_VULNERABLE) not in pairs


def test_jwt_scanner_asymmetric_vs_symmetric():
    inv = scan_path(FIXTURES / "jwt_config.json")
    details = {(f.detail, f.risk) for f in inv.findings if f.scanner == "jwt-alg"}
    assert ("RS256", QUANTUM_VULNERABLE) in details
    assert ("ES256", QUANTUM_VULNERABLE) in details
    assert ("HS256", UNKNOWN) in details  # symmetric MAC, not asymmetric-QV


def test_jwt_compact_token_header_decoded(tmp_path):
    # header {"alg":"RS256","typ":"JWT"} . payload {} . (no sig)
    token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ9.AAAA"
    p = tmp_path / "token.txt"
    p.write_text(f"Authorization: Bearer {token}\n")
    inv = scan_path(p)
    assert any(f.detail == "token:RS256" and f.risk == QUANTUM_VULNERABLE
               for f in inv.findings)


# --- whole mixed directory (acceptance #2) --------------------------------- #
def test_mixed_directory_scan_has_correct_tags():
    inv = scan_path(FIXTURES)
    pairs = _pairs(inv)
    # one of each risk class, exact tags:
    assert ("RSA", QUANTUM_VULNERABLE) in pairs
    assert ("ECDHE", QUANTUM_VULNERABLE) in pairs
    assert ("ML-KEM-768", PQC) in pairs
    assert ("X-Wing", HYBRID_READY) in pairs
    assert inv.files_scanned >= 4
    assert inv.limitations  # honesty: best-effort caveats always present


# --- Inventory JSON round-trip (acceptance #1) ----------------------------- #
def test_inventory_json_roundtrips_equal():
    inv = scan_path(FIXTURES)
    assert Inventory.from_json(inv.to_json()) == inv


def test_counts_by_risk_sums_to_total():
    inv = scan_path(FIXTURES)
    assert sum(inv.counts_by_risk().values()) == len(inv.findings)
