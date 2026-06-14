"""Crypto-agility discovery: a static, best-effort inventory of where crypto
lives in a codebase, tagged by quantum risk.

This module **reads and parses**; it never executes scanned code (guardrail #4 —
no security theater, and no arbitrary-code-execution footgun). It is honest about
its limits: a static scan has false negatives (dynamically built algorithm names,
reflection, compiled deps), so `Inventory.limitations` and per-`Finding.confidence`
are first-class, and the README says a clean scan is **not** proof of absence.

Quantum-risk tags for any algorithm that appears in the cited
`data/algorithms.json` table derive from that table's `quantum_secure`/`kind`
(single source of truth). Classical algorithms not in the PQC table use a small,
documented classical map.
"""

from __future__ import annotations

import ast
import base64
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .measure import load_algorithm_table

# Risk tags.
QUANTUM_VULNERABLE = "quantum-vulnerable"
HYBRID_READY = "hybrid-ready"
PQC = "pqc"
UNKNOWN = "unknown"

# Classical asymmetric primitives are not in the PQC sizes table; they are
# quantum-vulnerable by Shor. Documented here as the one classical source.
_CLASSICAL_QUANTUM_VULNERABLE = {
    "RSA", "DH", "ECDH", "ECDHE", "DHE",
    "ECDSA", "ECDSA-P256", "ECDSA-P384", "ECDSA-P521",
    "Ed25519", "Ed448",
}


def classify(algorithm: str) -> str:
    """Map a normalized algorithm name to a quantum-risk tag.

    PQC/hybrid tags come from the cited table; classical from the documented map.
    """
    table = load_algorithm_table()["algorithms"]
    if algorithm in table:
        e = table[algorithm]
        if not e["quantum_secure"]:
            return QUANTUM_VULNERABLE
        return HYBRID_READY if str(e["kind"]).startswith("hybrid") else PQC
    if algorithm in _CLASSICAL_QUANTUM_VULNERABLE:
        return QUANTUM_VULNERABLE
    return UNKNOWN


@dataclass(frozen=True)
class Finding:
    path: str
    line: int | None
    scanner: str          # python-ast | tls-config | certificate | jwt-alg | cryptokit
    detail: str           # the raw token/match
    algorithm: str | None  # normalized name, if identified
    risk: str
    confidence: str       # high | medium | low


@dataclass(frozen=True)
class Inventory:
    root: str
    files_scanned: int
    findings: tuple[Finding, ...]
    limitations: tuple[str, ...]

    def counts_by_risk(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.risk] = out.get(f.risk, 0) + 1
        return out

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Inventory:
        return cls(
            root=d["root"],
            files_scanned=d["files_scanned"],
            findings=tuple(Finding(**f) for f in d["findings"]),
            limitations=tuple(d["limitations"]),
        )

    @classmethod
    def from_json(cls, s: str) -> Inventory:
        return cls.from_dict(json.loads(s))


LIMITATIONS = (
    "Static best-effort scan: it can miss crypto built via dynamic/reflective "
    "names, string concatenation, or hidden in compiled/third-party binaries.",
    "Absence of findings is NOT proof that a file or project is quantum-safe.",
    "TLS/JWT/CryptoKit detection is pattern-based and may over- or under-match; "
    "certificate and Python-AST findings are parsed (higher confidence).",
)

_SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules", ".ruff_cache",
              ".pytest_cache", "build", "dist"}


# --------------------------------------------------------------------------- #
# Python AST scanner
# --------------------------------------------------------------------------- #
def _dotted(node: ast.AST) -> str:
    """Reconstruct a dotted name from an Attribute/Name/Call chain (best-effort)."""
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    if isinstance(node, ast.Attribute):
        return f"{_dotted(node.value)}.{node.attr}"
    if isinstance(node, ast.Name):
        return node.id
    return ""


# (dotted-name substring, normalized algorithm) — first match wins per node.
_PY_PATTERNS: tuple[tuple[str, str], ...] = (
    ("rsa.generate_private_key", "RSA"),
    ("RSAPrivateNumbers", "RSA"),
    ("SECP256R1", "ECDSA-P256"),
    ("SECP384R1", "ECDSA-P384"),
    ("SECP521R1", "ECDSA-P521"),
    ("ec.generate_private_key", "ECDSA"),
    ("X25519PrivateKey", "X25519"),
    ("X25519PublicKey", "X25519"),
    ("Ed25519PrivateKey", "Ed25519"),
    ("Ed448PrivateKey", "Ed448"),
    ("dh.generate_parameters", "DH"),
    ("DHParameterNumbers", "DH"),
)


def scan_python_source(path: Path, text: str) -> list[Finding]:
    """Find pyca/cryptography asymmetric usage via AST (never executes the code)."""
    try:
        tree = ast.parse(text, filename=str(path))
    except SyntaxError:
        return []
    findings: list[Finding] = []
    seen: set[tuple[int | None, str]] = set()  # collapse (line, algorithm) dupes
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Attribute, ast.Call, ast.Name)):
            continue
        dotted = _dotted(node)
        if not dotted:
            continue
        for needle, algo in _PY_PATTERNS:
            if needle in dotted:
                line = getattr(node, "lineno", None)
                if (line, algo) in seen:
                    break
                seen.add((line, algo))
                findings.append(Finding(
                    path=str(path), line=line,
                    scanner="python-ast", detail=dotted, algorithm=algo,
                    risk=classify(algo), confidence="high",
                ))
                break
    return findings


# --------------------------------------------------------------------------- #
# TLS config scanner
# --------------------------------------------------------------------------- #
# token -> normalized algorithm (key-exchange / group of interest)
_TLS_TOKENS: tuple[tuple[str, str], ...] = (
    ("X25519MLKEM768", "X-Wing"),        # IETF hybrid group name family -> hybrid
    ("SecP256r1MLKEM768", "X-Wing"),
    ("ECDHE", "ECDHE"),
    ("DHE", "DHE"),
    ("ECDH", "ECDH"),
    ("kRSA", "RSA"),
    ("X25519", "X25519"),
    ("prime256v1", "ECDSA-P256"),
    ("secp384r1", "ECDSA-P384"),
)
_TLS_DIRECTIVE = re.compile(
    r"(ssl_ciphers|ssl_protocols|ssl_ecdh_curve|ssl_conf_command|ciphersuites|"
    r"SSLCipherSuite|Ciphersuites|Groups|Curves)", re.IGNORECASE)


def scan_tls_config(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for i, line in enumerate(text.splitlines(), start=1):
        if not _TLS_DIRECTIVE.search(line):
            continue
        for token, algo in _TLS_TOKENS:
            # Word-boundary match so e.g. DHE/ECDH don't match inside ECDHE.
            if re.search(rf"\b{re.escape(token)}\b", line):
                findings.append(Finding(
                    path=str(path), line=i, scanner="tls-config",
                    detail=token, algorithm=algo, risk=classify(algo),
                    confidence="medium",
                ))
    return _dedupe(findings)


# --------------------------------------------------------------------------- #
# Certificate scanner
# --------------------------------------------------------------------------- #
def scan_certificate(path: Path, data: bytes) -> list[Finding]:
    """Parse PEM/DER cert(s) and report key type/size (all classical => QV)."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import (
            ec,
            ed448,
            ed25519,
            rsa,
        )
    except ImportError:  # pragma: no cover - cryptography is a hard dep
        return []

    certs = []
    if b"-----BEGIN CERTIFICATE-----" in data:
        blocks = re.findall(
            rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", data, re.DOTALL)
        for b in blocks:
            try:
                certs.append(x509.load_pem_x509_certificate(b))
            except Exception:  # noqa: BLE001 - skip unparseable block
                continue
    else:
        try:
            certs.append(x509.load_der_x509_certificate(data))
        except Exception:  # noqa: BLE001
            return []

    findings: list[Finding] = []
    for cert in certs:
        pub = cert.public_key()
        if isinstance(pub, rsa.RSAPublicKey):
            detail, algo = f"RSA/{pub.key_size}", "RSA"
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            detail, algo = f"EC/{pub.curve.name}", "ECDSA"
        elif isinstance(pub, ed25519.Ed25519PublicKey):
            detail, algo = "Ed25519", "Ed25519"
        elif isinstance(pub, ed448.Ed448PublicKey):
            detail, algo = "Ed448", "Ed448"
        else:  # pragma: no cover - exotic key type
            detail, algo = type(pub).__name__, None
        findings.append(Finding(
            path=str(path), line=None, scanner="certificate", detail=detail,
            algorithm=algo, risk=classify(algo) if algo else UNKNOWN,
            confidence="high",
        ))
    return findings


# --------------------------------------------------------------------------- #
# JWT alg scanner
# --------------------------------------------------------------------------- #
_JWT_ASYMMETRIC = {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
                   "ES256", "ES384", "ES512", "ES256K", "EdDSA"}
_JWT_SYMMETRIC = {"HS256", "HS384", "HS512"}
_JWT_ALG_IN_JSON = re.compile(r'"alg"\s*:\s*"([A-Za-z0-9]+)"')
_JWT_TOKEN = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")


def _jwt_risk(alg: str) -> tuple[str | None, str]:
    if alg in _JWT_ASYMMETRIC:
        return alg, QUANTUM_VULNERABLE
    if alg in _JWT_SYMMETRIC:
        return alg, UNKNOWN  # symmetric MAC; not an asymmetric PQC migration target
    return alg, UNKNOWN


def scan_jwt(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for i, line in enumerate(text.splitlines(), start=1):
        for m in _JWT_ALG_IN_JSON.finditer(line):
            algo, risk = _jwt_risk(m.group(1))
            findings.append(Finding(
                path=str(path), line=i, scanner="jwt-alg", detail=m.group(1),
                algorithm=None, risk=risk, confidence="medium"))
    # Decode any embedded compact JWTs (header is base64url JSON with "alg").
    for m in _JWT_TOKEN.finditer(text):
        header_b64 = m.group(0).split(".", 1)[0]
        try:
            pad = header_b64 + "=" * (-len(header_b64) % 4)
            header = json.loads(base64.urlsafe_b64decode(pad))
        except Exception:  # noqa: BLE001
            continue
        if isinstance(header, dict) and "alg" in header:
            algo, risk = _jwt_risk(str(header["alg"]))
            findings.append(Finding(
                path=str(path), line=None, scanner="jwt-alg",
                detail=f"token:{header['alg']}", algorithm=None, risk=risk,
                confidence="high"))
    return _dedupe(findings)


# --------------------------------------------------------------------------- #
# CryptoKit identifier scanner (Swift) — token pass over OUR fixtures
# --------------------------------------------------------------------------- #
_CRYPTOKIT_TOKENS: tuple[tuple[str, str], ...] = (
    ("XWingMLKEM768X25519", "X-Wing"),
    ("MLKEM1024", "ML-KEM-1024"),
    ("MLKEM768", "ML-KEM-768"),
    ("MLDSA87", "ML-DSA-87"),
    ("MLDSA65", "ML-DSA-65"),
    ("P256", "ECDSA-P256"),
    ("P384", "ECDSA-P384"),
    ("P521", "ECDSA-P521"),
    ("Curve25519", "X25519"),
    ("Ed25519", "Ed25519"),
)


def scan_cryptokit(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for i, line in enumerate(text.splitlines(), start=1):
        for token, algo in _CRYPTOKIT_TOKENS:
            if token in line:
                findings.append(Finding(
                    path=str(path), line=i, scanner="cryptokit", detail=token,
                    algorithm=algo, risk=classify(algo), confidence="medium"))
                break  # most-specific token first; one per line
    return _dedupe(findings)


# --------------------------------------------------------------------------- #
# Dispatch + walk
# --------------------------------------------------------------------------- #
def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple] = set()
    out: list[Finding] = []
    for f in findings:
        key = (f.path, f.line, f.scanner, f.detail, f.algorithm)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def _scan_file(path: Path) -> list[Finding]:
    suffix = path.suffix.lower()
    if suffix in {".pem", ".crt", ".cer", ".der"}:
        try:
            return scan_certificate(path, path.read_bytes())
        except OSError:
            return []
    try:
        text = path.read_text("utf-8", errors="ignore")
    except OSError:
        return []
    if suffix == ".py":
        return scan_python_source(path, text)
    if suffix == ".swift":
        return scan_cryptokit(path, text)
    findings: list[Finding] = []
    if suffix in {".conf", ".cfg", ".cnf", ".config", ".ini", ".txt", ""} or "conf" in path.name:
        findings += scan_tls_config(path, text)
    if suffix in {".json", ".jwt", ".txt", ".yaml", ".yml", ".env", ""}:
        findings += scan_jwt(path, text)
    return findings


def scan_path(path: str | Path) -> Inventory:
    """Scan a file or directory tree and return a risk-tagged :class:`Inventory`."""
    root = Path(path)
    files: list[Path] = []
    if root.is_file():
        files = [root]
    else:
        for p in sorted(root.rglob("*")):
            if p.is_file() and not any(part in _SKIP_DIRS for part in p.parts):
                files.append(p)

    findings: list[Finding] = []
    for f in files:
        findings.extend(_scan_file(f))

    return Inventory(
        root=str(root),
        files_scanned=len(files),
        findings=tuple(findings),
        limitations=LIMITATIONS,
    )
