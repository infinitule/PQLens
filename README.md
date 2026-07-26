# pqlens

> A lens on your post-quantum migration.

**Status: all 7 build phases complete. Pre-alpha, publish-pending. Do not use for production key material.**

---

## What pqlens does NOT do (read this first)

- ❌ **It is not a cryptographic implementation.** pqlens never implements ML-KEM,
  ML-DSA, SLH-DSA, AES, SHA-3/SHAKE, a DRBG, or an RNG. It *binds to and
  orchestrates* audited implementations only (OpenSSL ≥ 3.5, pyca/cryptography,
  optionally liboqs, and the OS CSPRNG).
- ❌ **It does not make raw crypto faster.** The fast path (formally-verified C,
  AVX2, AArch64, CUDA) is already solved upstream. pqlens does not compete there.
- ❌ **It is not an entropy source.** Its entropy work *measures* existing
  sources; the module imports no RNG and exposes no `generate`/`seed`/`random`
  function by design. Use `os.urandom`/`secrets` for production randomness.
- ❌ **It is not a compliance authority.** Its compliance statuses are advisory
  engineering signals from a cited data file — not legal determinations or a
  substitute for a formal audit.
- ❌ **It does not prove the absence of crypto.** Its discovery scan is
  best-effort and static; a clean scan is not a guarantee a project is quantum-safe.

## What pqlens does

Make post-quantum cryptography cheaper to **migrate to, measure, and operate**:

- **Cost / overhead measurement** — size, bandwidth, latency and energy deltas of
  PQC vs classical, so a team can price a migration before doing it. *(Phase 2 ✅)*
- **Crypto-agility discovery** — inventory where classical crypto lives in code,
  configs, and certs, tagged by quantum risk. *(Phase 3 ✅)*
- **Hybrid rollout helpers** — vetted-primitive-only hybrid KEM/signature
  wrappers with fail-closed downgrade detection. *(Phase 4 ✅)*
- **Entropy diagnostics** — H(p) and min-entropy estimators over a captured
  sample; **measurement only** (never an RNG). *(Phase 5 ✅)*
- **Compliance evidence** — map findings to FIPS 203/204/205, CNSA 2.0, EU
  roadmap (cited data file); export JSON + HTML, with a genuinely verifiable
  hybrid signature. *(Phase 6 ✅)*

## Quickstart (Phase 1)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .            # needs system OpenSSL >= 3.5 for ML-KEM

python -m pqlens --backends     # what audited backends are available here
python -m pqlens --selftest     # one ML-KEM-768 encap/decap, asserts secrets match
python -m pqlens --measure --algorithms ML-KEM-768,ML-KEM-1024   # price the migration
python -m pqlens --scan path/to/project   # inventory crypto, tagged by quantum risk
python -m pqlens --hybrid-selftest        # ML-KEM+X25519 KEM & ML-DSA+Ed25519 sig round-trips
python -m pqlens --entropy captured.bin   # measure a CAPTURED random sample (never generates one)
python -m pqlens --compliance path/ --sign --html report.html   # signed evidence (FIPS/CNSA/EU)
```

> **On `--compliance`:** verdicts come from a **cited data file**
> (`data/compliance.json`), not hardcoded logic, and are advisory engineering
> signals — not legal determinations. `--sign` produces a *genuinely verifiable*
> hybrid (ML-DSA+Ed25519) signature over the canonical JSON; with no key supplied
> it signs with an ephemeral key (proves integrity, not identity). Export is
> JSON + self-contained HTML (no bundled PDF lib — see `DECISIONS.md` D-006).

> **On `--entropy`:** pqlens **measures** a sample you already captured — it is
> not, and by design cannot be, a random number generator. The module imports no
> RNG and exposes no `generate`/`seed`/`random` function. For production
> randomness use `os.urandom` / `secrets`, not pqlens. A clean assessment is a
> diagnostic, not an SP 800-90B certification.

> **On hybrid mode:** signatures use the `PQ‖classical` layout and verify
> fail-closed (both halves must verify). The hybrid **KEM** combines ML-KEM and
> X25519 secrets with pyca's HKDF — this is the *generic* concat-then-KDF
> construction, **not** the certified X-Wing KEM. See `DECISIONS.md` D-005.

> **On `--scan`:** the inventory is a *best-effort static scan*. A clean result is
> **not** proof a project is quantum-safe — it can miss crypto built from dynamic
> names, reflection, or compiled dependencies. Every `Inventory` carries its
> `limitations` and every finding a `confidence`.

```python
import pqlens
r = pqlens.kem_roundtrip("ML-KEM-768")
print(r.backend, r.shared_secret_len, r.ciphertext_len, r.secrets_match)
```

## Guardrails

This project holds itself to four non-negotiable rules; see
[`DECISIONS.md`](DECISIONS.md):

1. Never implement a cryptographic primitive — only bind to audited ones.
2. Never weaken entropy — measure existing sources, never substitute them.
3. Constant-time discipline — no data-dependent branches on secret material in
   glue code.
4. No security theater — if a feature would create a false sense of safety, say
   so and refuse to ship it silently.

### Known limitation in this phase

The default ML-KEM/ML-DSA backend drives the OpenSSL **CLI**, so key/ciphertext/
shared-secret bytes transit a private `0700` temp dir (unlinked immediately,
never in `argv`). That is fine for smoke tests, benchmarks and demos, but it is
**not** how you should mint production keys. The backend is pluggable precisely so
an in-memory `liboqs` binding can replace it without any API change. See
[`DECISIONS.md`](DECISIONS.md) D-003.

## Threat model

**What pqlens helps against:** *blind migration*. Teams adopting PQC don't know
where their classical crypto lives, what the rollout will cost on the wire, which
algorithms meet which standard, or whether their captured entropy samples look
healthy. pqlens turns those unknowns into measured, cited numbers.

**What pqlens is explicitly NOT in scope for:**
- It is **not in your data path** and does not protect, store, or transport keys.
  A compromise of pqlens does not directly compromise your traffic — but do not
  feed it real long-lived secrets (the CLI backend writes to disk; D-003).
- It **trusts the audited backends** (OpenSSL, pyca). Their correctness/security
  is out of pqlens's scope by design — that is the point of not reimplementing.
- Its scanners are **static and best-effort**: an attacker (or just dynamic code)
  can hide crypto from them. Treat a clean scan as a lead, not a proof.
- Its compliance verdicts are **advisory**; the signature proves report
  *integrity*, and only *identity* if you sign with an attested organizational key.

## When NOT to use pqlens

- ❌ To **generate or custody production keys** — use a vetted KMS/HSM and the OS
  CSPRNG; pqlens's KEM/signature paths exist for measurement and demos.
- ❌ As a **randomness source** — it cannot be one by design.
- ❌ As a **substitute for a formal SP 800-90B entropy assessment** or a formal
  **compliance audit** — it produces evidence and diagnostics, not certifications.
- ❌ To **benchmark raw crypto speed** — the CLI backend's process-spawn cost
  dominates; pqlens headlines exact size deltas, not hot-loop timings.

## Public API

All exported from the top-level `pqlens` package (see `pqlens.__all__`):

| Area | Entry points |
|---|---|
| KEM | `get_kem_backend`, `kem_roundtrip`, `kem_roundtrip_selftest` |
| Cost measurement | `measure_migration_cost` → `MigrationCostReport` |
| Discovery | `scan_path` → `Inventory`, `classify` |
| Hybrid | `hybrid_sig_keygen`/`hybrid_sign`/`hybrid_verify`, `hybrid_kem_keygen`/`hybrid_encapsulate`/`hybrid_decapsulate` |
| Entropy (measure-only) | `assess_entropy` → `EntropyAssessment`, `binary_entropy` |
| Compliance | `build_compliance_report`, `sign_report`, `verify_report`, `report_to_html` |

CLI: `python -m pqlens [--backends | --selftest | --measure | --scan | --hybrid-selftest | --entropy | --compliance]`.

## License

Apache-2.0 — see [`LICENSE`](LICENSE). The Apple CryptoKit sample referenced in
[`REFERENCES.md`](REFERENCES.md) is a separate, read-only corpus under Apple's
own license; none of its code is vendored here.
