"""pqlens — a lens on your post-quantum migration.

pqlens makes post-quantum cryptography cheaper to **migrate to, measure, and
operate**. It is *not* a cryptographic implementation: every primitive comes
from an audited library (OpenSSL >= 3.5, pyca/cryptography, optionally liboqs).
See README.md and DECISIONS.md for the guardrails this project holds itself to.

The public surface is deliberately small and grows one phase at a time.
"""

from __future__ import annotations

# Defined before submodule imports: pqlens.measure does `from . import __version__`
# at import time, so this must exist before that import runs (avoids a circular
# partially-initialized-module error).
__version__ = "0.1.0"

from .backends import (  # noqa: E402 - must follow __version__ (see comment above)
    Encapsulation,
    KEMBackend,
    KeyPair,
    available_backends,
    get_kem_backend,
)
from .compliance import (  # noqa: E402
    ComplianceReport,
    build_compliance_report,
    report_to_html,
    sign_report,
    verify_report,
)
from .discover import Finding, Inventory, classify, scan_path  # noqa: E402
from .entropy import EntropyAssessment, assess_entropy, binary_entropy  # noqa: E402
from .errors import BackendError, BackendUnavailable, PqlensError  # noqa: E402
from .hybrid import (  # noqa: E402
    HybridEncapsulation,
    HybridKemKeypair,
    HybridSigKeypair,
    hybrid_decapsulate,
    hybrid_encapsulate,
    hybrid_kem_keygen,
    hybrid_kem_selftest,
    hybrid_sig_keygen,
    hybrid_sig_selftest,
    hybrid_sign,
    hybrid_verify,
)
from .kem import RoundtripResult, kem_roundtrip, kem_roundtrip_selftest  # noqa: E402
from .measure import (  # noqa: E402
    AlgorithmCost,
    EnergyEstimate,
    MigrationCostReport,
    Timing,
    measure_migration_cost,
)

__all__ = [
    "__version__",
    # errors
    "PqlensError",
    "BackendUnavailable",
    "BackendError",
    # backend contract + discovery
    "KEMBackend",
    "KeyPair",
    "Encapsulation",
    "available_backends",
    "get_kem_backend",
    # high-level KEM
    "RoundtripResult",
    "kem_roundtrip",
    "kem_roundtrip_selftest",
    # cost measurement (Phase 2)
    "measure_migration_cost",
    "MigrationCostReport",
    "AlgorithmCost",
    "Timing",
    "EnergyEstimate",
    # crypto-agility discovery (Phase 3)
    "scan_path",
    "Inventory",
    "Finding",
    "classify",
    # hybrid wrappers (Phase 4)
    "hybrid_sig_keygen",
    "hybrid_sign",
    "hybrid_verify",
    "hybrid_kem_keygen",
    "hybrid_encapsulate",
    "hybrid_decapsulate",
    "hybrid_sig_selftest",
    "hybrid_kem_selftest",
    "HybridSigKeypair",
    "HybridKemKeypair",
    "HybridEncapsulation",
    # entropy diagnostics (Phase 5, measurement only)
    "assess_entropy",
    "binary_entropy",
    "EntropyAssessment",
    # compliance evidence (Phase 6)
    "build_compliance_report",
    "sign_report",
    "verify_report",
    "report_to_html",
    "ComplianceReport",
]
