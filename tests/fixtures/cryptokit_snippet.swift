// pqlens discovery fixture (authored by pqlens, NOT copied from Apple's sample).
// A minimal CryptoKit-shaped snippet mixing classical + PQC identifiers so the
// token scanner has something to inventory. Never compiled or run.

import CryptoKit

func mixed() throws {
    // PQC KEM:
    let kemKey = try MLKEM768.PrivateKey()
    // PQC signature:
    let sigKey = try MLDSA65.PrivateKey()
    // Hybrid KEM (quantum-secure, hybrid-ready):
    let hybrid = try XWingMLKEM768X25519.PrivateKey()
    // Classical, quantum-vulnerable:
    let ecKey = P256.Signing.PrivateKey()
    _ = (kemKey, sigKey, hybrid, ecKey)
}
