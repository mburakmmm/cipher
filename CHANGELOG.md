# Changelog

All notable changes to Cipher will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-11-10

### Added
- **JSON Web Key (JWK) Standard Model (`jwk.nox`):** RFC 7517 compliant key model supporting RSA and symmetric octet keys (`kty`, `kid`, `alg`, `use`, `n`, `e`, `d`, `k`). Strict 2048-bit minimum key size enforcement.
- **Private Key Leakage Prevention:** `to_public_json()` enforces zero-leakage invariant, stripping all private exponents (`d`) and refusing public export of symmetric keys.
- **RFC 7638 SHA-256 Thumbprints:** Deterministic lexicographically-sorted thumbprint computation verified against official RFC 7638 Section 3.1 test vectors (`NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs`).
- **Algorithm Confusion Mitigation:** Verified immunity against public-key-as-symmetric-secret downgrade attacks.
- **Suite of 10 Comprehensive Test Suites (`tests/jwk_test.nox`, `tests/asymmetric_jws_test.nox`):** 100% pass rate (`10 passed, 0 failed`).

## [0.2.0] - 2026-11-10

### Added
- **JWT Claims Engine (`claims.nox`):** RFC 7519 and RFC 8725 compliant claims parser and validator. Strict temporal boundaries for `exp` (expiration), `nbf` (not before), and `iat` (issued at). Clock leeway tolerance, future timestamp rejection, and max token age enforcement. Exact string match for `iss` (issuer) and string/array matching for `aud` (audience).
- **JWT Verification & Typing (`jwt.nox`):** `VerifiedJwt` evidence type for authenticated payloads and strictly isolated `UnverifiedJwt` for diagnostic and debugging use. `JwtIssuer` and `JwtVerifier` high-level engines.
- **Purpose-Bound Signed Opaque Tokens (`signed_token.nox`):** Domain-separated, lightweight opaque tokens (`cip_opk_v1` prefix) with purpose binding and TTL constraints preventing cross-purpose token substitution.
- **Suite of 8 Comprehensive Test Suites (`tests/claims_test.nox`, `tests/jwt_test.nox`, `tests/signed_token_test.nox`):** 100% pass rate (`8 passed, 0 failed`).

## [0.1.0] - 2026-11-10

### Added
- **Phase 0:** Platform validation, toolchain verification, cross-platform GitHub Actions CI and Release Gate workflows.
- **Errors Hierarchy (`errors.nox`):** Comprehensive, strongly-typed `CipherError` hierarchy separating format, crypto, claims, and provider errors without leaking sensitive materials.
- **Strict Base64URL (`encoding.nox`):** RFC 4648 §5 and RFC 7515 §2 compliance (unpadded, whitespace/padding/invalid character rejection).
- **Strict JSON Parser (`json_strict.nox`):** RFC 8725 §3.10 duplicate key rejection, bounded 64KB sizes, and type-checked accessors.
- **Cryptographic Provider Abstraction (`provider.nox`):** `CryptoProvider` interface and `DefaultCryptoProvider` backed by verified OS entropy and `nox.crypto.hmac_sha256`. Minimum 32-byte (256-bit) secret enforcement.
- **Compact JWS Engine (`jws.nox`):** Standards-compliant JWS signing and verification over exact ASCII bytes with unconditional `alg=none` rejection, `crit` and `b64=false` rejection, and verifier-controlled algorithm allowlists.
- **Official RFC 7515 Vectors & Negative Tests:** Official RFC 7515 Section A.1 test vector and exhaustive negative test suite covering tampered signatures, tampered payloads, algorithm downgrades, kid mismatches, and duplicate header members (`5 passed, 0 failed`).
