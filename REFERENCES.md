# REFERENCES.md

External, audited material pqlens **draws on but does not vendor**. Each entry
records what it is, what it proves for us, and the license constraint. Sizes and
contracts taken from these are treated as *citations*, and pqlens still verifies
them against a live measurement before any report asserts them (guardrail #5).

---

## R-001 — Apple CryptoKit "QuantumSecurityWithCryptoKit" sample

- **Path (local, read-only corpus):**
  `/Users/f1thkdmlk24538/Desktop/HIMSHIKHAR/TECHNOLOGY/APPLE/EnhancingYourAppsPrivacyAndSecurityWithQuantumSecureWorkflows`
- **Upstream:** Apple Developer sample, "Enhancing your app's privacy and
  security with quantum-secure workflows"
  (developer.apple.com/documentation/cryptokit/).
- **License:** Apple Sample Code License — `LICENSE.txt` **is present** at the
  sample root (`Copyright 2025 Apple Inc.`). It is *permissive*: it grants use,
  reproduction, modification, and **redistribution in source/binary, with or
  without modifications**, provided redistributions retain the notice and you do
  not use Apple's name/marks to endorse derived products (BSD-style, "AS IS", no
  warranty).
- **Our policy (a choice, not a license requirement):** we still **reference it
  by path and author our own fixtures** rather than vendoring Apple's Swift —
  purely to keep this Apache-2.0 tree from mixing in Apple-licensed files. If we
  ever do vendor any of it, we must retain Apple's `LICENSE.txt` notice in those
  files and keep them under Apple's license (not relicense to Apache-2.0).
- **Requires:** iOS/macOS 26+ CryptoKit (the PQC APIs are gated behind
  `@available(... 26.0 ...)`).

### Why it matters to pqlens
It is a **second independent audited implementation** (Apple CryptoKit,
alongside our OpenSSL backend) that corroborates the PQC algorithm contracts,
and it is a realistic **mixed classical+PQC corpus** for the discovery phase.

### Algorithm inventory demonstrated (extracted from `Testing/`)
| Category | Types | pqlens relevance |
|---|---|---|
| **ML-KEM** (KEM) | `MLKEM768`, `MLKEM1024` — encapsulate/decapsulate | Same contract as our OpenSSL backend. ML-KEM-768 prints encapsulation=**1088 B**, shared secret=**32 B** at runtime → matches our live OpenSSL measurement. Cross-validates Phase 2 sizes. |
| **ML-DSA** (signature) | `MLDSA65`, `MLDSA87` — sign/verify, optional `context` | Signature/pubkey sizes (FIPS 204: ML-DSA-65 pk 1952 B / sig 3309 B; ML-DSA-87 pk 2592 B / sig 4627 B) — *cited, verified live in Phase 2*. |
| **PQ-HPKE** | `XWingMLKEM768X25519`, ciphersuite `XWingMLKEM768X25519_SHA256_AES_GCM_256` | A real **hybrid KEM** (X-Wing = ML-KEM-768 + X25519). Reference shape for Phase 4 hybrid KEM wrappers + Phase 2 hybrid-size example. |
| **Hybrid signature** | `MLDSA65xP256`, `MLDSA87xP384` | Concatenation layout `PQSignature ‖ ECSignature`, verified by splitting at `PQSignatureSize`. **Vetted reference for Phase 4 hybrid-signature wrappers** (order: PQ first, then classical EC). |
| Secure Enclave variants | `SecureEnclave.MLKEM*/MLDSA*` | Notes that PQC keys can be hardware-backed; informational. |
| Classical (for discovery) | `P256.Signing`, `P384.Signing`, `X25519` | Targets the Phase 3 scanner must tag: P256/P384 alone = quantum-vulnerable; inside X-Wing / hybrid sig = hybrid-ready. |

### How each phase consumes it
- **Phase 2 (measure):** cross-check the params table against this
  implementation's contract; use X-Wing as a concrete hybrid-KEM size example.
- **Phase 3 (discover):** use the `Testing/` + `Views/` Swift as a discovery
  **fixture corpus**, and extend the scanner to recognize CryptoKit identifiers
  (`MLKEM768`, `MLDSA65`, `XWingMLKEM768X25519`, `P256.Signing`, ...) with the
  risk tags above. (Phase 3's original scope was Python-AST + configs + certs +
  JWT; CryptoKit/Swift recognition is an additive, language-agnostic identifier
  pass — kept separate and clearly labeled.)
- **Phase 4 (hybrid wrappers):** mirror Apple's `PQ ‖ EC` concatenation order
  and X-Wing hybrid KEM; cite this sample + the IETF drafts for the wire layout.
