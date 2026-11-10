# ADR 0001: Asymmetric Crypto Provider & JWK Standard Model

- **Status:** Accepted
- **Date:** 2026-11-10
- **RFC References:** RFC 7517 (JWK), RFC 7518 (JWA), RFC 7638 (JWK Thumbprint), RFC 8725 §3.2 (Algorithm Confusion)

## Context

Cipher requires supporting public key representations (JSON Web Key / JWK, RFC 7517), deterministic thumbprint generation (RFC 7638), and asymmetric signature verification (RS256, RSA PKCS#1 v1.5 with SHA-256).

Security requirements mandate:
1. Public JWKS export must **never** export private key material (`d`, `p`, `q`, `dp`, `dq`, `qi` or symmetric `k`).
2. Verification of RS256 must enforce a minimum RSA modulus length of 2048 bits.
3. Strict immunity to **Algorithm Confusion** attacks: A public key's modulus/exponent or PEM representation must never be coerced into an HMAC secret key.

## Decision

1. **JWK Model (`jwk.nox`):**
   - Provide strongly-typed `JwkKey` supporting `kty="RSA"` and `kty="oct"`.
   - Implement `to_public_json()` which strips all secret material and CRT parameters unconditionally.
   - Implement RFC 7638 deterministic thumbprint computation sorting required parameters lexicographically (`e`, `kty`, `n` for RSA).
2. **Provider Separation:**
   - Extend `CryptoProvider` with `verify_rs256(modulus_b64: str, exponent_b64: str, signing_input: str, sig_raw: str) -> bool`.
   - Enforce distinct type contracts for symmetric vs. asymmetric key holders to eliminate algorithm confusion at compile/runtime boundaries.
3. **Fail-Closed Verification:**
   - Reject RSA moduli with bit length < 2048 bits.
   - Reject corrupted signatures, missing `n` or `e` parameters, and unrecognized key types.
