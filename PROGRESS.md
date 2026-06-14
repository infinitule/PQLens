# PROGRESS.md

Append-only. Newest phase at top. On a fresh session, read this file +
`NEXT_PROMPT.md` first, then resume.

---

## Phase 7 — Packaging, docs, honest README  ✅ PASSED GATE (FINAL build phase)
**Date:** 2026-06-14
**Status:** complete — all acceptance tests green, critique gate passed. All 7
  build phases done.
**Built:** Apache-2.0 `LICENSE`, `CHANGELOG.md`, `src/pqlens/py.typed`; README
  expanded with Threat model + "When NOT to use this" + public-API table (still
  leads with "what pqlens does NOT do"); `pyproject` ships data + py.typed;
  `tests/test_packaging.py`; CI `package` job (build wheel → clean-venv install →
  assert data tables shipped).
**Verified:** `103 passed`, `ruff` clean, **coverage 92% (floor 88)**. Wheel +
  sdist build; wheel contains both data tables + py.typed; clean-venv
  `pip install dist/*.whl` then `pqlens --backends` exits 0 and `--compliance`
  loads all 5 standards from the packaged data.
**Next:** NO further build. `COMMERCIAL_NEXT.md` written (design only). DO NOT
  publish or build the commercial layer without explicit approval.

### Self-critique checklist (section 3) — answered in writing
1. **Reimplemented a primitive?** No — docs/packaging phase; zero crypto changes.
2. **Branch on secret data?** No new code paths touch secrets.
3. **New functions tested incl. edges?** Packaging tests: every `__all__` export
   importable, data tables are package resources, README first-H2 is "does NOT
   do", LICENSE is Apache, built wheel contains data + py.typed. 103 tests, 92%.
4. **Dependency added?** `build`/`hatchling` are build-time/dev only (both
   permissive); no new runtime dependency.
5. **Claim without a number/citation?** No. README's "does NOT do" claims map to
   DECISIONS D-003/005/006 and the guardrails; nothing overstated.
6. **API smaller than planned?** No API growth — packaging only. `__all__` is the
   curated surface; a test forbids dangling exports.
7. **Skeptical reviewer's one objection:** *"README honesty can rot as code
   changes."* Mitigated: a test pins the README to lead with "does NOT do", and
   the "does NOT do" bullets are tied to versioned DECISIONS entries rather than
   prose that can drift silently.
8. **Optimized a non-bottleneck?** No.

**Gate decision:** all 7 build phases passed their gates. Stop; await approval
before any publish/commercial work.

---

## Phase 6 — Compliance evidence  ✅ PASSED GATE
**Date:** 2026-06-14
**Status:** complete — all acceptance tests green, critique gate passed.
**Built:** `compliance.py` — `build_compliance_report()` composes the discovery
  `Inventory` → frozen `ComplianceReport` (JSON round-trips) mapped to FIPS
  203/204/205, CNSA 2.0, EU roadmap via the cited `data/compliance.json` (verdicts
  in data, not code); `sign_report()`/`verify_report()` (genuinely verifiable
  hybrid ML-DSA+Ed25519 over canonical JSON, fail-closed); `report_to_html()`
  evidence pack; CLI `--compliance <path> [--sign] [--html FILE] [--json]`. Added
  `hybrid_verify_detached()` (verify from publics).
**Verified:** `97 passed`, `ruff` clean, **coverage 92% (floor 88 in CI)**.
  Real demo on the Apple sample: FIPS-203/204 compliant; CNSA-2.0 distinguishes
  compliant (ML-KEM-1024/ML-DSA-87) vs below-required-level (768/65) vs
  non-compliant (ECDSA/X25519). Signature verifies True; one-byte tamper → False.
**Next:** Phase 7 — packaging + honest README (see `NEXT_PROMPT.md`).

### Self-critique checklist (section 3) — answered in writing
1. **Reimplemented a primitive?** No. Mapping is data + a generic engine; signing
   reuses the Phase-4 hybrid (ML-DSA via OpenSSL, Ed25519 via pyca); digest via
   `hashlib`.
2. **Branch on secret data?** No. Verification compares a public SHA-256 digest
   and delegates to the fail-closed `hybrid_verify_detached` (constant-time inside).
3. **New functions tested incl. edges?** Yes — JSON round-trip, data-driven proof
   (mutate table → report changes), specificity (1024 beats family rule),
   sign→verify True, tamper→False, signed JSON round-trip still verifies, unsigned
   fails verify, HTML embeds signature, CLI human/json/sign/html. 97 tests, 92%.
4. **Dependency added?** None — stdlib `hashlib`/`base64` + existing crypto. No
   PDF library (D-006).
5. **Claim without a number/citation?** No. Every standard carries a citation;
   EU rows are marked advisory; unverifiable binding dates are NOT asserted.
6. **API smaller than planned?** Held — `build_compliance_report`/`sign_report`/
   `verify_report`/`report_to_html` + dataclasses.
7. **Skeptical reviewer's one objection:** *"'Signed' compliance reports are
   usually theater, and an ephemeral key signs nothing meaningful."* Addressed:
   the signature is genuinely re-verifiable (tamper test proves it), and we
   explicitly label the ephemeral-key case as integrity-not-identity in the
   signature `caveat` + README + D-006, and allow passing an org key. Unsigned
   reports are labeled "UNSIGNED DRAFT". (Guardrail #4.)
8. **Optimized a non-bottleneck?** No. Straight-line composition; the scan is the
   cost, already characterized in Phase 3.

**Gate decision:** no blocking "no/unsure" → advance to Phase 7.

---

## Phase 5 — Entropy diagnostics (measurement only)  ✅ PASSED GATE
**Date:** 2026-06-14
**Status:** complete — all acceptance tests green, critique gate passed.
**Built:** `entropy.py` — `assess_entropy(sample)` → frozen `EntropyAssessment`
  (JSON round-trips): Shannon bits/byte, SP 800-90B §6.3.1 MCV min-entropy
  (conservative 99% bound), advisory verdict + caveats; `binary_entropy(p)`
  H(p) diagnostic. CLI `--entropy <file> [--json]`.
**Verified:** `80 passed`, `ruff` clean, **coverage 92% (floor 88 in CI)**.
  Real CLI: /dev/urandom → 7.98 Shannon / 6.96 min-entropy / verdict ok;
  /dev/zero → 0 / 0 / verdict suspect.
**Next:** Phase 6 — compliance evidence (see `NEXT_PROMPT.md`).

### Self-critique checklist (section 3) — answered in writing
1. **Reimplemented a primitive?** No. Pure measurement math (`math.log2`,
   `Counter`); no crypto.
2. **Branch on secret data?** N/A here, and importantly **guardrail #2**: the
   module is measurement-only by construction — it imports NO RNG and has NO
   generate/seed/random function. A test (`test_module_exposes_no_randomness...`)
   enforces this, plus an AST check that os/secrets/random are never imported.
3. **New functions tested incl. edges?** Yes — H(p) endpoints/midpoint/range,
   all-identical, urandom, biased (MCV<Shannon), tiny-sample verdict, empty,
   non-bytes, JSON round-trip, the guardrail-#2 shape test, CLI human/json/missing.
   80 tests, coverage 92%.
4. **Dependency added?** None — stdlib only for this module.
5. **Claim without a number/citation?** No. Min-entropy cites SP 800-90B §6.3.1
   MCV with the exact Z; verdict thresholds are labeled heuristic/advisory; the
   "NOT a certification" caveat is always present.
6. **API smaller than planned?** Yes — `assess_entropy` + `binary_entropy` +
   one frozen dataclass. No knobs.
7. **Skeptical reviewer's one objection:** *"People will treat a green entropy
   verdict as permission to use the sample as keying material."* Mitigated three
   ways: every assessment's first caveat forbids exactly that and points to
   os.urandom/secrets; the verdict is named advisory; and the module *cannot*
   emit randomness by design. No security theater (guardrail #4/#2).
8. **Optimized a non-bottleneck?** No. Single O(n) pass over the sample; no
   premature work.

**Gate decision:** no blocking "no/unsure" → advance to Phase 6.

---

## Phase 4 — Hybrid wrappers (KEM + signature)  ✅ PASSED GATE
**Date:** 2026-06-14
**Status:** complete — all acceptance tests green, critique gate passed.
**Built:** `hybrid.py` — `hybrid_sign/verify` (ML-DSA‖Ed25519, fail-closed) and
  `hybrid_encapsulate/decapsulate` (ML-KEM‖X25519, HKDF combiner); new
  `OpenSSLSignatureBackend` (ML-DSA, verified 3309-B sig) + `SignatureBackend`
  protocol + `get_signature_backend()`; `_exec.run(check=False)` for fail-closed
  verify; CLI `--hybrid-selftest`.
**Verified:** `66 passed`, `ruff` clean, **coverage 91% (floor 88 in CI)**.
  `--hybrid-selftest` → PASS (KEM+SIG). Downgrade tests prove: bit-flip in either
  half, or truncation to one half, all verify False.
**Next:** Phase 5 — entropy diagnostics (measurement only; see `NEXT_PROMPT.md`).

### Self-critique checklist (section 3) — answered in writing
1. **Reimplemented a primitive?** No — including the combiner: secrets are mixed
   with `cryptography`'s HKDF-SHA256. ML-DSA via OpenSSL, Ed25519/X25519 via pyca.
2. **Branch on secret data?** No. Secret/sig comparison via `hmac.compare_digest`;
   length checks are on public lengths. Verify is fail-closed.
3. **New functions tested incl. edges?** Yes — sig round-trip, tamper-PQ-half,
   tamper-classical-half, truncate-to-one-half (downgrade), wrong-message, KEM
   round-trip, corrupt-either-component, wrong-length ct, bad X25519 pubkey,
   unknown algos, sig-backend registry, CLI. 66 tests, coverage 91%.
4. **Dependency added?** None — uses existing `cryptography` (Ed25519/X25519/HKDF)
   + OpenSSL. No `hypothesis` (kept property-style as explicit cases).
5. **Claim without a number/citation?** No. Sig/ct sizes asserted vs table
   (ML-DSA-65 sig 3309, ML-KEM-768 ct 1088 +32). Combiner construction documented.
6. **API smaller than planned?** Held — 6 wrapper fns + 2 selftests + 3 frozen
   dataclasses; signature backend mirrors the KEM one.
7. **Skeptical reviewer's one objection:** *"Calling this hybrid KEM 'X-Wing'
   would overstate the assurance."* Correct — so we DON'T: it's the generic
   concat+HKDF construction, labeled as such in code, the `HYBRID_KEM_SCHEME`
   constant, README, and DECISIONS.md D-005. No security theater (guardrail #4).
8. **Optimized a non-bottleneck?** No. Correctness/safety-only; each op still
   spawns OpenSSL (the known Phase-2 cost), not tuned.

**Gate decision:** no blocking "no/unsure" → advance to Phase 5.

---

## Phase 3 — Crypto-agility discovery  ✅ PASSED GATE
**Date:** 2026-06-14
**Status:** complete — all acceptance tests green, critique gate passed.
**Built:** `discover.scan_path()` → frozen `Inventory` (JSON round-trips) of
  risk-tagged `Finding`s from 5 scanners: Python-AST, TLS-config, X.509 cert,
  JWT-alg, CryptoKit-identifier. Added ML-DSA-44/65/87 (FIPS 204) to the cited
  table so PQC tags stay single-source; `measure` now refuses non-KEM entries.
  CLI `--scan <path> [--json]`. Our own fixtures (no Apple code vendored).
**Verified:** `51 passed`, `ruff` clean, **coverage 90% (floor 88 in CI)**.
  Real-world demo: scanned the actual Apple CryptoKit sample → 39 files, 64
  findings (pqc=38, hybrid-ready=5 X-Wing, quantum-vulnerable=21 EC/Curve25519).
**Next:** Phase 4 — hybrid KEM + signature wrappers (see `NEXT_PROMPT.md`).

### Self-critique checklist (section 3) — answered in writing
1. **Reimplemented a primitive?** No. Scanners parse/pattern-match; the cert
   scanner only reads public-key metadata via `cryptography.x509`.
2. **Branch on secret data?** No. Discovery touches no secret material — it reads
   source/config/cert *public* artifacts; it never executes scanned code.
3. **New functions tested incl. edges?** Yes — per-scanner tests, exact risk
   tags, JSON round-trip, mixed-dir, JWT symmetric-vs-asymmetric, compact-token
   decode, cert from a generated PEM, word-boundary TLS, non-KEM measure guard,
   CLI human/json. 51 tests, coverage 90%.
4. **Dependency added?** None. Uses stdlib `ast`/`re`/`base64` + already-present
   `cryptography`.
5. **Claim without a number/citation?** No. PQC/hybrid tags derive from the cited
   table's `quantum_secure`; classical tags from a documented in-module map;
   ML-DSA sizes cited to FIPS 204.
6. **API smaller than planned?** Yes — one public `scan_path()` + `classify()` +
   `Inventory`/`Finding`. Scanners are internal.
7. **Skeptical reviewer's one objection:** *"A static scanner gives false
   confidence — a clean scan isn't proof of quantum-safety."* Exactly why
   `Inventory.limitations` and per-finding `confidence` are first-class and the
   README leads the `--scan` section with that caveat (guardrail #4). We do not
   claim completeness.
8. **Optimized a non-bottleneck?** No. Plain single-pass scanning; no premature
   indexing/caching. Profiling would be premature at fixture scale.

**Gate decision:** no blocking "no/unsure" → advance to Phase 4.

---

## Phase 2 — Cost / overhead measurement core  ✅ PASSED GATE
**Date:** 2026-06-14
**Status:** complete — all acceptance tests green, critique gate passed.
**Built:** `measure.measure_migration_cost()` → frozen `MigrationCostReport`
  (JSON round-trips) with static sizes, X25519 handshake delta, warmup+variance
  benchmarks, and a labeled energy model; versioned cited `data/algorithms.json`
  (FIPS 203 + RFC 7748 + X-Wing draft, 3-way agreement for ML-KEM-768);
  `baselines.py` (X25519 via pyca); CLI `--measure [--algorithms --iterations --json]`.
**Verified:** `36 passed`, `ruff` clean, **coverage 91% (floor 88 in CI)**. Live
  numbers: ML-KEM-768 = 2272 B handshake (35.5×), ML-KEM-1024 = 3136 B (49×),
  X-Wing = 2336 B (36.5×). Subprocess spawn ≈60–80 ms/call — quantified + flagged.
**Next:** Phase 3 — crypto-agility discovery (see `NEXT_PROMPT.md`).

### Self-critique checklist (section 3) — answered in writing
1. **Reimplemented a primitive?** No. ML-KEM via OpenSSL, X25519 via pyca;
   `measure` only times calls and counts public bytes.
2. **Branch on secret data?** No. Size/energy logic uses public sizes; the live
   roundtrip compares secrets with `hmac.compare_digest` (constant-time) and
   otherwise compares only lengths.
3. **New functions tested incl. edges?** Yes — JSON round-trip, FIPS-size
   assertion, live size+secret verification, monotonic deltas, variance stats,
   energy provenance, subprocess-overhead, cited-only (X-Wing), X25519 baseline,
   unknown algo/baseline, CLI human/json/error. 36 tests, coverage 91%.
4. **Dependency added?** `pytest-cov` (dev only, MIT). No new *runtime* dep —
   `cryptography` was already declared in Phase 1 and is now actually used.
5. **Claim without a number/citation?** No. Sizes cited (FIPS 203 / RFC 7748 /
   X-Wing draft) and live-verified; energy explicitly `estimated=True` with
   assumptions+sources; timings carry variance; spawn overhead is measured.
6. **API smaller than planned?** Yes — one public function
   (`measure_migration_cost`) + 4 frozen report dataclasses. No extra knobs.
7. **Skeptical reviewer's one objection:** *"Your benchmarks are dominated by a
   ~60–80 ms subprocess spawn — they're near-useless as crypto timings."* True,
   and we surface it: `subprocess_overhead_ms` quantifies the floor,
   `backend_overhead_note` says treat size deltas as primary and use an
   in-process liboqs backend for real timings. We did not hide it.
8. **Optimized a non-bottleneck?** No. We measured as-is and reported the
   subprocess cost honestly rather than tuning it away (which would distort the
   measurement).

**Gate decision:** no blocking "no/unsure" → advance to Phase 3.

---

## Phase 1 — Skeleton & contracts  ✅ PASSED GATE
**Date:** 2026-06-14
**Status:** complete — all acceptance tests green, critique gate passed.
**Built:** pluggable `KEMBackend` contract + OpenSSL ML-KEM backend (binds system
  `openssl` 3.6.2 CLI), runtime backend registry, high-level `kem_roundtrip`,
  `python -m pqlens` CLI (`--selftest`/`--backends`), full scaffold + CI + docs.
**Verified:** `17 passed` (pytest), `ruff` clean; `--selftest` ML-KEM-768 &
  ML-KEM-1024 PASS with matching 32-byte secrets / spec-correct ciphertext sizes.
**Next:** Phase 2 — cost/overhead measurement core (see `NEXT_PROMPT.md`).

### Self-critique checklist (section 3) — answered in writing
1. **Did I reimplement any crypto primitive?** No. ML-KEM runs entirely inside
   OpenSSL ≥ 3.5; pqlens only moves bytes and shells out.
2. **Does any glue code branch on secret data?** No. Secret-vs-secret comparison
   uses `hmac.compare_digest` (constant-time). No `if secret == ...` anywhere.
3. **Are all new functions covered by tests, incl. failure/edge cases?** Yes:
   roundtrip (all 3 ML-KEM sizes), implicit-rejection on tampered ciphertext,
   unknown/unavailable backend, unsupported algorithm, error formatting, CLI.
   17 tests. (Coverage % not yet wired — added to Phase-2 acceptance.)
4. **Did I add a dependency? Maintained/audited/license-compatible?** Runtime:
   `cryptography` (pyca, BSD/Apache-2.0, actively maintained, audited) — present
   but not yet *used* (lands in Phase 2's classical baseline). `liboqs-python`
   left as optional extra (MIT). Dev: `pytest` (MIT), `ruff` (MIT). All
   permissive, compatible with our Apache-2.0.
5. **Any claim without a number or citation?** No. Sizes (32B secret, 768/1088/
   1568B ciphertext) are asserted against `ML_KEM_PARAMS` (NIST FIPS 203 params)
   and verified by a live roundtrip.
6. **Is the public API smaller than the plan wanted?** Yes — I declined to stub
   all six future modules. `__all__` is 12 names, all backed by working code.
7. **Would a skeptical security reviewer find this honest? Their one objection:**
   *"A CLI binding that writes the shared secret to disk is not something to mint
   production keys from."* Acknowledged in `DECISIONS.md` D-003 and the README;
   backend is pluggable so an in-memory liboqs binding replaces it with no API
   change. We do not claim production-key safety.
8. **Performance reality-check — optimized a non-bottleneck?** No optimization
   done; correctness-only phase. (Benchmarking is Phase 2's actual job, with
   warmup + variance, so we measure the real thing rather than guess.)

**Gate decision:** no checklist answer is "no/unsure" in a blocking way →
advance to Phase 2.
