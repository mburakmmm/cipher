# Supported Cryptographic Algorithms — Cipher

| Algorithm | RFC | Key Type | Minimum Key Size | Status & Security Profile |
|---|---|---|---|---|
| **HS256** | RFC 7518 §3.2 | Symmetric (`oct`) | 256 bits (32 bytes) | **Production Active**: Verified against RFC 7515 A.1 vectors; constant-time MAC checks |
| **RS256** | RFC 7518 §3.3 | Asymmetric (`RSA`) | 2048 bits (342 Base64URL chars / 256 bytes) | **JWK / Thumbprint Active**: Algorithm confusion strictly prevented. Runtime signature verify gated by ADR-0001 FFI. |
| **none** | RFC 7518 §3.6 | None | N/A | **Unconditionally Rejected** (`DisallowedAlgorithmError`) |

## Security Invariants

1. **Algorithm Allowlist (Verifier-Controlled):**
   The verification algorithm is dictated exclusively by `VerificationProfile.allowed_algs`. An attacker cannot alter trust paths by modifying the token's `alg` header.
2. **Algorithm Confusion Immunity:**
   Symmetric secrets and asymmetric public keys use incompatible type representations. An RSA public key passed as an HMAC secret will fail allowlist validation.
3. **Key Length Enforcement:**
   - HMAC secret keys must have a byte length >= 32 (256 bits).
   - RSA keys must have a modulus bit length >= 2048 bits (at least 342 Base64URL characters).
4. **Explicit Typing (`typ`):**
   When `VerificationProfile.expected_typ` is set, headers must strictly match the declared token type (RFC 8725 §3.11).
