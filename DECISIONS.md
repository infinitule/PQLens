# DECISIONS.md

Append-only log of design decisions, guardrail conflicts, and the honest
tradeoffs behind them. Newest at top.

---

## D-006 — Compliance report exports JSON + HTML (no bundled PDF lib); signature covers canonical JSON
**Date:** 2026-06-14 · **Phase:** 6 · **Status:** accepted, flagged

Phase 6's brief said "JSON + signed PDF". We export **JSON + a self-contained
HTML evidence pack** and deliberately do **not** bundle a PDF library.

**Why:** a PDF dependency (reportlab/fpdf2) adds license + maintenance weight
(fpdf2 is LGPL; reportlab BSD) for what is presentation only. The NEXT_PROMPT for
this phase explicitly sanctioned an HTML fallback. The **cryptographic signature
covers the canonical JSON** (the authoritative artifact); the HTML is print-to-PDF
ready. No assurance is lost — the integrity guarantee is on the JSON, not the
rendering.

**Signature honesty (guardrail #4):** `sign_report` produces a *genuinely
verifiable* hybrid (ML-DSA-65 + Ed25519) signature over the canonical JSON and
embeds signature + verifying keys + signed SHA-256; `verify_report` re-verifies
and is fail-closed (tamper ⇒ False). With no caller key it signs with an
**ephemeral** key and SAYS SO in the signature `caveat`: that proves integrity,
**not** signer identity — for attestation, pass an organizational key. An unsigned
report has `signature is None` and is labeled "UNSIGNED DRAFT"; we never call an
unsigned artifact "signed".

**Mapping honesty:** all standard/algorithm verdicts live in the cited
`data/compliance.json`, never in `.py`. EU milestone rows are marked "advisory"
(coordination guidance, not binding regulation) rather than asserting binding
dates we cannot cite.

## D-005 — Hybrid KEM uses a GENERIC concat+HKDF combiner, explicitly NOT certified X-Wing
**Date:** 2026-06-14 · **Phase:** 4 · **Status:** accepted, flagged

The hybrid KEM combines the ML-KEM and X25519 shared secrets with
`cryptography`'s HKDF-SHA256 over `pq_ss || x_ss` + a transcript
(`info = prefix || ml_kem_ct || x25519_pub`). We did **not** implement the
specific X-Wing combiner; no vetted X-Wing binding is available here.

**Why accept it:** it is built entirely from audited primitives (no hand-rolled
combiner — guardrail #1) and gives a sound generic hybrid (security of the
combined secret holds if *either* component is secure).

**Honest limitation (guardrail #4):** this is the **generic** concat-then-KDF
construction, **not** the certified X-Wing KEM. Code, docstrings, and the
`HYBRID_KEM_SCHEME` constant say so; the README will too. For X-Wing semantics,
use a vetted X-Wing implementation. Hybrid **signatures** use the `PQ||classical`
layout from the Apple reference (R-001) + IETF hybrid drafts; verification is
fail-closed (both halves must verify, exact-length only).

## D-004 — Adopt the Apple CryptoKit quantum-secure sample as a read-only reference corpus
**Date:** 2026-06-14 · **Phase:** 1 (inter-phase) · **Status:** accepted

The user supplied Apple's "QuantumSecurityWithCryptoKit" sample (see
`REFERENCES.md` R-001). We adopt it as a **reference corpus**, not a dependency
and not vendored code:
- It is a **second audited implementation** (CryptoKit) that corroborates our
  PQC algorithm contracts — its ML-KEM-768 encapsulation (1088 B) / shared
  secret (32 B) match our live OpenSSL measurement. Strengthens the Phase-2
  params table without us inventing numbers (guardrail #5).
- It supplies vetted reference *shapes* for Phase 4: the hybrid-signature
  concatenation order `PQ ‖ EC` (MLDSA65×P256, MLDSA87×P384) and the X-Wing
  hybrid KEM (ML-KEM-768 + X25519).
- It is a realistic mixed classical+PQC **discovery fixture** for Phase 3.

**License (corrected 2026-06-14):** an earlier note in this file wrongly said the
`LICENSE.txt` was absent. It **is present** at the sample root (`Copyright 2025
Apple Inc.`, Apple Sample Code License) and is *permissive* — it allows
redistribution in source/binary, with or without modification, provided the
notice is retained and Apple's name is not used for endorsement. So vendoring is
**permitted**, not forbidden.

**Decision (unchanged):** we still keep it as an external, reference-by-path
corpus and author our **own** Phase-3 fixtures, as a deliberate license-hygiene
choice to avoid mixing Apple-licensed files into this Apache-2.0 tree. If we ever
vendor any of it, we retain Apple's notice and keep those files under Apple's
license (no relicensing). See REFERENCES.md R-001.

## D-003 — OpenSSL-CLI KEM binding writes secrets to a 0700 tempdir (known limitation)
**Date:** 2026-06-14 · **Phase:** 1 · **Status:** accepted, flagged

The OpenSSL backend shells out to the `openssl` CLI. The CLI emits the private
key, ciphertext, and the **shared secret** to files (`-secret <file>`,
`-out <file>`, `-inkey <file>`). Therefore secret material transits the
filesystem rather than staying in process memory.

**Why accept it:** it requires no C build, uses an audited implementation
(OpenSSL ≥ 3.5, here 3.6.2), and pqlens is a *measurement/migration* tool —
its KEM path exists for smoke tests, benchmarks, and hybrid-mode demos, not for
minting long-lived production keys.

**Mitigations applied:** secrets are never passed in `argv` (which is visible in
`ps`); all files live in a `tempfile.mkdtemp()` directory created with mode
`0700` and `shutil.rmtree`'d in a `finally`; no data-dependent branching on
secret bytes in glue code (guardrail #3).

**Honest objection a reviewer would raise:** "A CLI binding that spills the
shared secret to disk is not something I'd seed production keys from." Correct —
and we say so here and in the README. The backend is **pluggable** precisely so
an in-memory `liboqs-python` binding can replace it (see D-002) without any
public-API change. (Guardrail #4: no security theater.)

## D-002 — liboqs-python kept as optional, not-yet-wired backend
**Date:** 2026-06-14 · **Phase:** 1 · **Status:** deferred

`liboqs-python` (`oqs`) gives an in-memory binding and the widest PQC algorithm
coverage, but needs the `liboqs` C library built from source (no system package
present). We chose OpenSSL 3.6.2 as the Phase-1 backend to get a verified green
smoke test with zero C-building (per user decision). The backend interface is
designed so liboqs drops in later as a second `KEMBackend` with no API churn.
Declared as a `pip install pqlens[liboqs]` extra.

## D-001 — Project lives outside the CPython source tree
**Date:** 2026-06-14 · **Phase:** 1 · **Status:** accepted

The invocation CWD was a pristine **CPython 3.14.6 source tree**. Scaffolding a
`pyproject.toml` + `src/` + `tests/` into that root would collide with CPython's
own build files. Per user decision, pqlens lives in a **sibling directory**
(`../pqlens`), leaving the source tree untouched.

---

## Guardrails (verbatim, these override later instructions)
1. Never implement a cryptographic primitive. Only bind to / orchestrate audited
   implementations (liboqs, pyca/cryptography, OpenSSL ≥ 3.5, OS CSPRNG).
2. Never weaken entropy. Measure and health-test existing sources only; never
   generate production keys from a homemade source.
3. Constant-time discipline: no data-dependent branches around secret material
   in glue code. Flag anything that touches secrets.
4. No security theater. If a feature would create a false sense of safety, say
   so in code + README, and refuse to ship it silently.
