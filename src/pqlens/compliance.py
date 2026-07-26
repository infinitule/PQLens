"""Compliance evidence — map discovered crypto to standards, sign the result.

Composes the discovery `Inventory` (and optionally an `EntropyAssessment`) into a
machine-readable `ComplianceReport`, mapping each algorithm to FIPS 203/204/205,
CNSA 2.0, and the EU PQC roadmap.

Honesty discipline this module holds (guardrail #4 — compliance is the easiest
thing to fake):
  * **The verdict mapping lives entirely in `data/compliance.json`** (versioned +
    cited). This module is a generic engine; it hardcodes no standard ID and no
    algorithm->status mapping (a test greps this file to prove it).
  * **"Signed" means genuinely verifiable.** `sign_report` signs the canonical
    report bytes with the audited hybrid signature (ML-DSA + Ed25519) and embeds
    the signature, verifying keys, and the signed SHA-256. `verify_report`
    re-verifies and is fail-closed; tampering one byte makes it False. An unsigned
    report says so (`signature is None`); we never label it "signed".
  * Statuses are advisory engineering signals, not legal determinations; where a
    binding requirement is not citable, the data file uses status "advisory".
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import asdict, dataclass, replace
from importlib import resources
from typing import Any

from . import __version__
from .discover import Inventory, scan_path
from .entropy import EntropyAssessment
from .hybrid import (
    HybridSigKeypair,
    hybrid_sig_keygen,
    hybrid_sign,
    hybrid_verify_detached,
)
from .measure import load_algorithm_table


def load_compliance_table() -> dict[str, Any]:
    """Load the versioned, cited algorithm->standard mapping shipped in the package."""
    raw = resources.files("pqlens.data").joinpath("compliance.json").read_text("utf-8")
    return json.loads(raw)


def _family(algorithm: str) -> str:
    """Resolve an algorithm's family from the cited algorithms table, else derive it."""
    table = load_algorithm_table()["algorithms"]
    if algorithm in table:
        return str(table[algorithm]["family"])
    if algorithm.startswith("ML-KEM"):
        return "ML-KEM"
    if algorithm.startswith("ML-DSA"):
        return "ML-DSA"
    if algorithm.startswith("ECDSA"):
        return "ECDSA"
    if algorithm in {"ECDHE", "ECDH"}:
        return "ECDH"
    if algorithm in {"DHE", "DH"}:
        return "DH"
    if algorithm in {"Ed25519", "Ed448"}:
        return "EdDSA"
    return algorithm


@dataclass(frozen=True)
class ComplianceFinding:
    algorithm: str
    family: str
    status: str
    rationale: str


@dataclass(frozen=True)
class StandardAssessment:
    standard: str
    title: str
    citation: str
    status: str                       # worst status across findings
    findings: tuple[ComplianceFinding, ...]


@dataclass(frozen=True)
class ReportSignature:
    scheme: str
    pq_algorithm: str
    pq_public_b64: str
    classical_public_b64: str
    signature_b64: str
    signed_sha256: str
    caveat: str


@dataclass(frozen=True)
class ComplianceReport:
    generated_by: str
    target: str
    standards: tuple[StandardAssessment, ...]
    summary: dict[str, Any]
    entropy_verdict: str | None
    caveats: tuple[str, ...]
    signature: ReportSignature | None

    # -- canonical / serialization ---------------------------------------
    def _body_dict(self) -> dict[str, Any]:
        """Deterministic dict of everything EXCEPT the signature (what gets signed)."""
        d = asdict(self)
        d.pop("signature", None)
        return d

    def canonical_json(self) -> str:
        return json.dumps(self._body_dict(), sort_keys=True, separators=(",", ":"))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ComplianceReport:
        standards = tuple(
            StandardAssessment(
                standard=s["standard"], title=s["title"], citation=s["citation"],
                status=s["status"],
                findings=tuple(ComplianceFinding(**f) for f in s["findings"]),
            )
            for s in d["standards"]
        )
        sig = ReportSignature(**d["signature"]) if d.get("signature") else None
        return cls(
            generated_by=d["generated_by"], target=d["target"], standards=standards,
            summary=d["summary"], entropy_verdict=d.get("entropy_verdict"),
            caveats=tuple(d["caveats"]), signature=sig,
        )

    @classmethod
    def from_json(cls, s: str) -> ComplianceReport:
        return cls.from_dict(json.loads(s))


def _worst_status(statuses: list[str], rank: dict[str, int]) -> str:
    relevant = [s for s in statuses if rank.get(s, -1) >= 0]
    if not relevant:
        return "not-applicable"
    return max(relevant, key=lambda s: rank.get(s, -1))


def _best_rule_for(algorithm: str, family: str, standard: str, rules: list[dict]) -> dict | None:
    """Most-specific matching rule for (algorithm, standard): exact algorithm > family."""
    best: dict | None = None
    best_spec = -1
    for rule in rules:
        m = rule["match"]
        if standard not in rule["assessments"]:
            continue
        if m.get("algorithm") == algorithm:
            spec = 2
        elif m.get("family") == family:
            spec = 1
        else:
            continue
        if spec > best_spec:
            best_spec, best = spec, rule["assessments"][standard]
    return best


def build_compliance_report(
    target: str | Inventory,
    *,
    entropy: EntropyAssessment | None = None,
) -> ComplianceReport:
    """Build an (unsigned) compliance report for a path or a prebuilt Inventory."""
    inventory = target if isinstance(target, Inventory) else scan_path(target)
    table = load_compliance_table()
    standards_meta = table["standards"]
    rules = table["rules"]
    rank = table["severity_rank"]

    algorithms = sorted({f.algorithm for f in inventory.findings if f.algorithm})

    assessments: list[StandardAssessment] = []
    for std_id, meta in standards_meta.items():
        findings: list[ComplianceFinding] = []
        for algo in algorithms:
            fam = _family(algo)
            matched = _best_rule_for(algo, fam, std_id, rules)
            if matched:
                findings.append(ComplianceFinding(
                    algorithm=algo, family=fam,
                    status=matched["status"], rationale=matched["rationale"],
                ))
        assessments.append(StandardAssessment(
            standard=std_id, title=meta["title"], citation=meta["citation"],
            status=_worst_status([f.status for f in findings], rank),
            findings=tuple(findings),
        ))

    summary = {
        "algorithms_assessed": len(algorithms),
        "standards": {a.standard: a.status for a in assessments},
        "inventory_findings": len(inventory.findings),
    }
    caveats = [
        "Advisory engineering signals, not legal determinations. Statuses derive "
        "from the cited data/compliance.json; consult counsel for binding obligations.",
        "Completeness is bounded by the discovery scan (best-effort, static) — see "
        "the Inventory's own limitations; absence of a finding is not proof of absence.",
    ]
    entropy_verdict = None
    if entropy is not None:
        entropy_verdict = entropy.verdict
        caveats.append(
            f"Entropy assessment included (verdict={entropy.verdict}, "
            f"min-entropy={entropy.min_entropy_bits_per_byte:.2f} bits/byte); "
            "measurement only, not an SP 800-90B certification."
        )

    return ComplianceReport(
        generated_by=f"pqlens {__version__}",
        target=inventory.root,
        standards=tuple(assessments),
        summary=summary,
        entropy_verdict=entropy_verdict,
        caveats=tuple(caveats),
        signature=None,
    )


# --------------------------------------------------------------------------- #
# Signing / verification (genuinely verifiable — not theater)
# --------------------------------------------------------------------------- #
def sign_report(
    report: ComplianceReport, *, keypair: HybridSigKeypair | None = None
) -> ComplianceReport:
    """Sign a report's canonical bytes with the hybrid (ML-DSA + Ed25519) signature.

    With no ``keypair`` an EPHEMERAL one is generated: that proves the report's
    integrity (tamper-evidence relative to the embedded key) but NOT signer
    identity. Pass your organization's keypair for attestation.
    """
    ephemeral = keypair is None
    kp = keypair or hybrid_sig_keygen()
    body = report.canonical_json().encode("utf-8")
    sig = hybrid_sign(kp, body)
    signature = ReportSignature(
        scheme=f"hybrid:{kp.pq_algorithm}+Ed25519",
        pq_algorithm=kp.pq_algorithm,
        pq_public_b64=base64.b64encode(kp.pq_public).decode(),
        classical_public_b64=base64.b64encode(kp.classical_public).decode(),
        signature_b64=base64.b64encode(sig).decode(),
        signed_sha256=hashlib.sha256(body).hexdigest(),
        caveat=(
            "Signed with an EPHEMERAL key: proves integrity, not signer identity. "
            "Supply an organizational key for attestation."
            if ephemeral else
            "Signed with a caller-supplied key."
        ),
    )
    return replace(report, signature=signature)


def verify_report(report: ComplianceReport) -> bool:
    """Re-verify a signed report. Fail-closed: False if unsigned, tampered, or bad sig."""
    s = report.signature
    if s is None:
        return False
    body = report.canonical_json().encode("utf-8")
    if hashlib.sha256(body).hexdigest() != s.signed_sha256:
        return False
    try:
        sig = base64.b64decode(s.signature_b64)
        pq_pub = base64.b64decode(s.pq_public_b64)
        ed_pub = base64.b64decode(s.classical_public_b64)
    except (ValueError, TypeError):
        return False
    return hybrid_verify_detached(s.pq_algorithm, pq_pub, ed_pub, body, sig)


# --------------------------------------------------------------------------- #
# Human-readable HTML evidence pack (no external dependency; print-to-PDF ready)
# --------------------------------------------------------------------------- #
def report_to_html(report: ComplianceReport) -> str:
    """Render a self-contained HTML evidence pack. See DECISIONS.md D-006 on why
    HTML (not a bundled PDF library): the cryptographic signature covers the
    canonical JSON, which is the authoritative artifact."""
    def esc(x: object) -> str:
        return (str(x).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))

    rows = []
    for a in report.standards:
        rows.append(f"<h3>{esc(a.standard)} — {esc(a.title)} "
                    f"<span class='st st-{esc(a.status)}'>{esc(a.status)}</span></h3>")
        rows.append(f"<p class='cite'>{esc(a.citation)}</p><table>"
                    "<tr><th>algorithm</th><th>family</th><th>status</th><th>rationale</th></tr>")
        for f in a.findings:
            rows.append(f"<tr><td>{esc(f.algorithm)}</td><td>{esc(f.family)}</td>"
                        f"<td class='st-{esc(f.status)}'>{esc(f.status)}</td>"
                        f"<td>{esc(f.rationale)}</td></tr>")
        rows.append("</table>")
    sig_html = "<p><b>UNSIGNED DRAFT</b> — not cryptographically signed.</p>"
    if report.signature is not None:
        s = report.signature
        sig_html = (f"<p><b>Signature</b>: {esc(s.scheme)}<br>signed SHA-256: "
                    f"<code>{esc(s.signed_sha256)}</code><br>{esc(s.caveat)}</p>")
    caveats = "".join(f"<li>{esc(c)}</li>" for c in report.caveats)
    return (
        "<!doctype html><meta charset='utf-8'><title>pqlens compliance</title>"
        "<style>body{font:14px system-ui;margin:2rem;max-width:60rem}"
        "table{border-collapse:collapse;width:100%;margin:.5rem 0}"
        "td,th{border:1px solid #ccc;padding:.3rem .5rem;text-align:left;font-size:13px}"
        ".st{font-size:12px;padding:.1rem .4rem;border-radius:3px}"
        ".st-non-compliant{color:#a00;font-weight:bold}.st-below-required-level{color:#b60}"
        ".st-advisory{color:#06c}.st-compliant{color:#080}.cite{color:#666;font-size:12px}"
        "</style>"
        f"<h1>pqlens compliance evidence</h1><p>{esc(report.generated_by)} · "
        f"target: <code>{esc(report.target)}</code></p>"
        f"{''.join(rows)}{sig_html}<h3>Caveats</h3><ul>{caveats}</ul>"
    )
