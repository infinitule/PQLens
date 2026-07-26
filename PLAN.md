# PLAN.md — pqlens

> A lens on your post-quantum migration. A Python library + CLI that makes PQC
> **cheaper to migrate to, measure, and operate** — it does **not** implement
> cryptography.

This file always holds the plan for the **current** phase. History lives in
`PROGRESS.md`; the auto-generated next sub-prompt lives in `NEXT_PROMPT.md`.

---

## Phase 7 — Packaging, docs, honest README  (CURRENT, final build phase)

### Goal
Make pqlens publish-ready (but DO NOT publish — await approval). Mostly docs +
packaging polish; no new features.

### Work
- README leads with **what pqlens does NOT do**, then adds a **Threat model**,
  **When NOT to use this**, and a **public-API table**.
- Add `LICENSE` (Apache-2.0) at root, `CHANGELOG.md`, `src/pqlens/py.typed`.
- `pyproject.toml`: ensure `data/*.json` + `py.typed` ship in the wheel.
- Build wheel + sdist; assert the wheel contains the data files; install the
  wheel in a clean venv and run `pqlens --backends`.
- `tests/test_packaging.py`; CI wheel job.

### Acceptance tests
1. Every name in `pqlens.__all__` is importable (no dangling exports).
2. Built wheel contains `pqlens/data/algorithms.json` + `compliance.json` (+ py.typed).
3. Clean-venv `pip install dist/*.whl` then `python -m pqlens --backends` exits 0.
4. README's first H2 is the "does NOT do" section.
5. Coverage >= 88%; ruff clean.

### After Phase 7 → REGEN
Write `COMMERCIAL_NEXT.md` (design only, no build); then STOP and ask before any
publish or commercial build.

---

## Phase 5 — Entropy diagnostics (MEASUREMENT ONLY)  (DONE — see PROGRESS.md)

### Goal
`pqlens.entropy.assess_entropy(sample: bytes) -> EntropyAssessment`. Measure a
**supplied** byte sample; never produce randomness (guardrail #2, designed in).

### Guardrail #2, enforced by design (not just docs)
- The module imports **no** RNG (`os.urandom`/`secrets`/`random` are absent).
- **No** function named `generate*`/`seed*`/`random*`/`rng*`/`drbg*`; **no**
  function returns bytes. Sample in → numbers + caveats out. A test asserts this.
- `os.urandom`/`secrets` are referenced in docs as "use these, not pqlens".

### What it reports
- `binary_entropy(p)` — H(p) diagnostic (H(0)=H(1)=0, H(0.5)=1).
- Shannon entropy per byte (0..8).
- Min-entropy via the **SP 800-90B §6.3.1 Most-Common-Value** estimator
  (conservative upper-bound on p_max, 99% CI → `-log2(p_u)`), cited + caveated.
- `sample_bytes`, `distinct_values`, advisory `verdict`
  (ok|suspect|insufficient-data) + `caveats` incl. "NOT an SP 800-90B
  certification".

### Files
`src/pqlens/entropy.py`; `tests/test_entropy.py`; CLI `--entropy <file> [--json]`
(reads a captured sample file; never creates one).

### Acceptance tests
1. `EntropyAssessment` frozen; `to_json()/from_json()` round-trip equal.
2. `H(0)==H(1)==0`, `H(0.5)==1.0`.
3. All-identical bytes → Shannon≈0, min-entropy≈0, verdict suspect.
4. `os.urandom(N)` large (generated **in the test**, not the lib) → Shannon/byte
   near 8, min-entropy meaningfully > 0.
5. 90%-one-value biased sample → min-entropy < Shannon (MCV catches hidden bias).
6. **API-shape test:** module exposes no randomness-emitting / generate/seed/
   random callable (guardrail #2 enforced by test).
7. Coverage floor held >= 88%.

### Honesty constraints (carried)
- Every number cites its method; verdict is advisory only, never an
  authorization to use the sample as a key source.

---

## Phase 4 — Hybrid wrappers (KEM + signature)  (DONE — see PROGRESS.md)

### Goal
Thin, vetted-primitive-only hybrid wrappers with **fail-closed** downgrade
detection. Verified on this machine: OpenSSL ML-DSA-65 sign/verify works
(3309-byte sig; tampered msg rejected).

### Decisions for this phase
- **Add a minimal OpenSSL ML-DSA signature backend** (`SignatureBackend`
  protocol + `OpenSSLSignatureBackend`), reusing `_exec` 0700-tempdir discipline
  (same D-003 on-disk-secret caveat). `openssl pkeyutl -verify` returns non-zero
  on signature mismatch → add a non-raising `check=False` mode to `_exec.run`;
  `verify()` is fail-closed (True only on clean exit 0).
- **Classical half = Ed25519** (fixed 64-byte sig, no DER variability) via pyca.
- **Hybrid signature wire = `PQsig ‖ Ed25519sig`**, split at the table's fixed
  `signature_bytes` (Apple-style known-size split). Length mismatch ⇒ reject.
- **Hybrid KEM = ML-KEM ‖ X25519**, secrets combined with **`cryptography` HKDF**
  (NOT a hand-rolled combiner). Documented as the *generic* concat-then-KDF
  construction, explicitly **not certified X-Wing** (guardrail #4).

### Files
`backends/base.py` (+`SigKeyPair`,`SignatureBackend`); `backends/openssl_sig.py`;
`registry.py` (+`get_signature_backend`); `_exec.py` (+`check`);
`hybrid.py` (4 wrappers + dataclasses + draft-version constants);
`tests/test_hybrid.py`; CLI `--hybrid-selftest`.

### Acceptance tests
1. Hybrid sig round-trips True; bit-flip PQ half → False; bit-flip classical half
   → False; truncate to one half → False (fail-closed).
2. Hybrid KEM: both parties derive the same combined secret; corrupting either
   component changes/fails it.
3. Wrappers reject mismatched/short inputs with a clear error, not a crash.
4. Concatenated output sizes match table-derived expectations.
5. Coverage floor held >= 88%.

### Honesty constraints (carried)
- No hand-rolled crypto incl. the KDF combiner; constant-time compares; fail
  closed on any partial/missing half; document draft versions in constants.

---

## Phase 3 — Crypto-agility discovery  (DONE — see PROGRESS.md)

### Goal
`pqlens.discover.scan_path(path) -> Inventory`: static, best-effort inventory of
crypto usage, each finding risk-tagged `quantum-vulnerable | hybrid-ready | pqc |
unknown`. AST/parse only — never execute scanned code.

### Scanners (smallest useful set)
1. Python AST — RSA / EC(P256/384/521) / X25519 / Ed25519 / DH via pyca call+name patterns.
2. TLS config — ciphersuite/group tokens (ECDHE/DHE/RSA → QV; `X25519MLKEM768` → hybrid-ready).
3. Certificates — PEM/DER via `cryptography.x509`: key type+size (classical → QV).
4. JWT `alg` — RS/PS/ES/EdDSA → QV; HS* → unknown (symmetric, noted).
5. CryptoKit identifiers (.swift token pass, OUR fixtures): MLKEM/MLDSA → pqc,
   XWing → hybrid-ready, P256/P384/X25519/Ed25519 → QV.

### Single source of truth
Risk for any algorithm in `data/algorithms.json` derives from its
`quantum_secure`+`kind`. **Add ML-DSA-44/65/87 (FIPS 204) to the table** so PQC
signature tags come from it too; classical algos (RSA/ECDSA/Ed25519/DH/JWT) use a
small *documented* classical map. `measure` now refuses non-KEM table entries.

### Files
`src/pqlens/discover.py` (`Finding`, `Inventory`, `scan_path`, scanners);
`tests/fixtures/` (OUR OWN mixed py/conf/jwt/swift; cert generated in-test);
`tests/test_discover.py`; CLI `--scan <path> [--json]`.

### Acceptance tests
1. `Inventory` frozen; `to_json()/from_json()` round-trip equal.
2. Mixed fixture → exact risk tag per finding (RSA QV, ECDHE QV, ML-KEM pqc, X-Wing hybrid-ready).
3. AST finds `rsa.generate_private_key` + `ec.SECP256R1` → QV.
4. Cert scanner reads a `cryptography`-generated RSA-2048 PEM → `RSA/2048`, QV.
5. CryptoKit pass: `XWingMLKEM768X25519` → hybrid-ready; bare `P256.Signing` → QV.
6. PQC tags derive from the table's `quantum_secure` (no second source of truth).
7. Coverage floor held >= 88%.

### Honesty constraints (carried from Phase-2 critique)
- `Inventory.limitations` + per-`Finding.confidence`; README: scan is best-effort,
  NOT proof of absence (guardrail #4).
- Never execute scanned code (AST/parse only).
- API tiny: one `scan_path()` + dataclasses + internal scanners.

---

## Phase 2 — Cost / overhead measurement core  (DONE — see PROGRESS.md)

### Goal
One public entrypoint, `measure_migration_cost(algorithms, *, baseline, iterations)`,
returning a typed, JSON-round-trippable `MigrationCostReport`. Report = per
algorithm: static sizes (cited), handshake byte delta vs an X25519 baseline,
keygen/encap/decap benchmarks (warmup + variance), and a clearly-labeled energy
model. Honest about the OpenSSL-CLI subprocess overhead.

### Files
| File | Purpose |
|---|---|
| `src/pqlens/data/algorithms.json` | Versioned size/param table w/ citations (FIPS 203 + RFC 7748 + X-Wing draft), live-verifiable flags. Inside the package so it ships in the wheel. |
| `src/pqlens/baselines.py` | X25519 baseline via pyca/cryptography: sizes + a real ephemeral exchange for timing. |
| `src/pqlens/measure.py` | `MigrationCostReport`, `AlgorithmCost`, `Timing`, `EnergyEstimate`, `measure_migration_cost(...)`, internal bench helper (`statistics`). |
| `src/pqlens/__main__.py` | add `--measure --algorithms A,B [--iterations N] [--json]` (flag style, keeps Phase-1 CLI intact). |
| `tests/test_measure.py`, `tests/test_baselines.py` | acceptance + edge cases. |

### Acceptance tests
1. `MigrationCostReport` frozen; `to_json()`/`from_json()` round-trip equal.
2. Table sizes asserted vs FIPS 203 (ML-KEM-768: pk 1184, ct 1088, ss 32) and a
   **live** roundtrip confirms ct+ss byte lengths == table (OpenSSL backend).
3. Handshake delta vs X25519 positive for every PQC algorithm; monotonic
   1024 > 768 > 512.
4. Each benchmark has mean/median/stdev/min, `iterations >= 5` after warmup,
   stdev >= 0.
5. Energy fields carry `estimated=True` + non-empty assumptions + sources.
6. Coverage floor wired (`--cov=pqlens --cov-fail-under=<met value>`).

### Honesty constraints carried from Phase-1 critique
- Numbers trace to a measurement or a citation (`size_sources`, energy
  `sources`/`assumptions`). 3-way agreement recorded for ML-KEM-768 (OpenSSL
  live · CryptoKit sample · FIPS 203 — see REFERENCES.md R-001).
- **Do not optimize crypto** — measure as-is.
- OpenSSL CLI pays process-spawn overhead → timings measure "CLI", not
  "hot library". Quantify it (`subprocess_overhead_ms` by timing a no-op
  `openssl version`) and headline the *exact* size deltas over the caveated
  timings. (Guardrail #4.)
- API stays tiny: one public function + the report dataclasses.

### Deviation from NEXT_PROMPT
Table is JSON inside `src/pqlens/data/` (not top-level `data/*.toml`) so it ships
in the wheel and loads via `importlib.resources`. Recorded here.

---

## Phase 1 — Skeleton & contracts  (DONE — see PROGRESS.md)

### Goals
1. Repo scaffold: `pyproject.toml`, `src/pqlens/`, `tests/`, CI config.
2. A small, typed **public contract** for KEM operations via a pluggable
   backend, with at least one real backend.
3. A smoke test that performs **one ML-KEM-768 encapsulate/decapsulate** through
   an audited implementation and asserts shared-secret equality.
4. Governance files: `DECISIONS.md`, `PROGRESS.md`, `NEXT_PROMPT.md`.

### Non-goals (resist scope creep — see CRITIQUE gate)
- No `measure`, `discover`, `hybrid`, `entropy`, or `compliance` code yet. Those
  are later phases; stubbing all six now is surface area without substance.
- No hand-rolled crypto. Ever. (Guardrail #1.)
- No CLI surface beyond what the smoke test needs (a `--selftest` is enough).

### Architecture decided this phase
- **Backend abstraction** (`pqlens.backends.base.KEMBackend`): a typed Protocol
  with `keygen() -> KeyPair`, `encapsulate(public_key) -> Encapsulation`,
  `decapsulate(secret_key, ciphertext) -> bytes`.
- **OpenSSL backend** (`pqlens.backends.openssl`): binds to the system
  `openssl` ≥ 3.5 CLI (verified 3.6.2 here) for ML-KEM. This is an
  *orchestration* of an audited implementation, not a reimplementation.
- **liboqs backend**: left as a documented, optional, not-yet-wired adapter so a
  pure in-memory binding can replace OpenSSL later without API changes.
- **Backend registry** (`pqlens.backends.registry`): discovers which audited
  backends are actually available at runtime; raises a clear error otherwise.

### Files to create
| File | Purpose |
|---|---|
| `pyproject.toml` | Package metadata, deps (`cryptography`; `liboqs` optional extra), pytest config |
| `src/pqlens/__init__.py` | Version + curated public exports (`__all__`) |
| `src/pqlens/errors.py` | `PqlensError`, `BackendUnavailable`, `BackendError` |
| `src/pqlens/_exec.py` | Hardened subprocess + 0700 tempdir helper (no secrets in argv) |
| `src/pqlens/backends/base.py` | `KEMBackend` Protocol + `KeyPair`/`Encapsulation` dataclasses |
| `src/pqlens/backends/openssl.py` | OpenSSL ML-KEM binding |
| `src/pqlens/backends/registry.py` | Runtime backend discovery |
| `src/pqlens/kem.py` | High-level `kem_roundtrip_selftest()` + thin orchestration |
| `src/pqlens/__main__.py` | `python -m pqlens --selftest` |
| `tests/test_smoke_mlkem.py` | The required ML-KEM-768 encap/decap equality test |
| `tests/test_backends.py` | Registry + error-path tests |
| `.github/workflows/ci.yml` | Lint + test on push |
| `DECISIONS.md`, `PROGRESS.md`, `NEXT_PROMPT.md` | Governance/recursion |

### Acceptance tests (phase fails if any is red)
1. `python -m pytest` is green.
2. ML-KEM-768 roundtrip: `ssA == ssB`, `len(ss) == 32`, `len(ct) == 1088`.
3. Decapsulating a **tampered** ciphertext does **not** raise but yields a
   shared secret `!=` the real one (ML-KEM implicit rejection) — asserts we are
   faithfully exposing the primitive's real behavior, not papering over it.
4. With no audited backend available, the public API raises `BackendUnavailable`
   with an actionable message (tested via monkeypatch).
5. `python -m pqlens --selftest` exits 0 and prints a one-line PASS.

### Risks
- **Secrets transit the filesystem** with a CLI binding (OpenSSL writes the
  shared secret + key to files). Mitigation: 0700 tempdir, immediate unlink,
  never in argv. Flagged in `DECISIONS.md` as a known limitation of this backend
  vs. an in-memory liboqs binding. (Guardrail #3 / #4.)
- OpenSSL CLI surface differs across 3.5/3.6/4.0. Mitigation: pin behavior to
  the `-encap`/`-decap`/`genpkey -algorithm ML-KEM-768` interface and assert the
  version at backend init.
- `cryptography` wheels for Python 3.14 — confirmed installable in this env.

### Guardrail check for this phase
- [x] No primitive implemented — we shell out to OpenSSL.
- [x] No data-dependent branching on secrets in glue code.
- [x] Entropy/RNG untouched this phase.
