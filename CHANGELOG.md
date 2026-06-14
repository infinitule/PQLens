# Changelog

All notable changes to pqlens. Pre-alpha; the API may change.

## [0.1.0] — unreleased (publish pending approval)

Built recursively in seven phases (see `PROGRESS.md` for the per-phase gate and
self-critique record). Every phase: measurement/orchestration only — **no
cryptographic primitive is implemented**; pqlens binds to OpenSSL ≥ 3.5,
pyca/cryptography, and the OS CSPRNG.

### Added
- **KEM backend & contracts** — pluggable `KEMBackend`; OpenSSL ML-KEM backend
  (ML-KEM-512/768/1024); `kem_roundtrip`; `python -m pqlens --selftest/--backends`.
- **Migration-cost measurement** — `measure_migration_cost()` → `MigrationCostReport`
  (sizes, X25519 handshake delta, warmup+variance benchmarks, labeled energy
  model); cited `data/algorithms.json`; `--measure`.
- **Crypto-agility discovery** — `scan_path()` → risk-tagged `Inventory` from
  Python-AST / TLS-config / certificate / JWT / CryptoKit scanners; `--scan`.
- **Hybrid wrappers** — `hybrid_sign/verify` (ML-DSA‖Ed25519, fail-closed) and
  `hybrid_encapsulate/decapsulate` (ML-KEM‖X25519, HKDF combiner); ML-DSA
  signature backend; `--hybrid-selftest`.
- **Entropy diagnostics (measurement only)** — `assess_entropy()` (Shannon +
  SP 800-90B §6.3.1 MCV min-entropy), `binary_entropy()`; `--entropy`. No RNG by
  design (guardrail #2).
- **Compliance evidence** — `build_compliance_report()` mapped via cited
  `data/compliance.json` to FIPS 203/204/205, CNSA 2.0, EU roadmap;
  `sign_report()/verify_report()` (genuinely verifiable hybrid signature);
  `report_to_html()`; `--compliance [--sign --html --json]`.
- **Packaging & honest docs** — Apache-2.0 LICENSE, `py.typed`, README that leads
  with what pqlens does NOT do, threat model, and "when NOT to use this".

### Honesty notes (see DECISIONS.md)
- D-003: the OpenSSL-CLI backend transits secrets through a 0700 tempdir — not
  for minting production keys.
- D-005: the hybrid KEM is the generic concat+HKDF construction, **not** certified
  X-Wing.
- D-006: compliance statuses are advisory (not legal); "signed" reports are
  genuinely re-verifiable; ephemeral signing = integrity, not identity.

### Not done (by design)
- No published package (awaiting approval). No commercial layer (design only, in
  `COMMERCIAL_NEXT.md`).
