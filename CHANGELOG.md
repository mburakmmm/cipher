# Changelog

All notable changes to Cipher will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2026-11-10

### Fixed & Hardened (Technical SOL Audit)
- **KeyRing Validate-Before-Commit & Atomic Rollback (`keyring.nox`):** Fixed critical consistency vulnerability where a failed rotation would leave the keyring without an active signer. Pre-validates `trust_domain`, unique `kid`, and key states before mutating active signers. On validation failure, previous active keys remain in `STATE_ACTIVE_SIGNING` (rollback guarantee).
- **JWKS SSRF & IP Range Controls (`jwks.nox`):** Expanded `is_safe_jwks_url()` to cover all `127.0.0.0/8` loopbacks, IPv6 loopback (`::1`, `[::1]`), IPv6 link-local/ULA (`fe80::`, `fc00::`), cloud metadata, link-local `169.254.0.0/16`, and all 16 subnets of RFC 1918 `172.16.0.0/12`.
- **JWKS Bounded Negative Cache (`jwks.nox`):** Added `MAX_NEGATIVE_CACHE_ENTRIES` (256) with FIFO eviction, protecting against memory exhaustion attacks during high-volume unknown `kid` floods.
- **Strict Integer NumericDate Validation (`json_strict.nox`):** Rejects fractional numeric timestamps in `exp`, `nbf`, `iat` with `JsonFormatError` (`float(i) == val.n`).
- **Explicit Token Typing (`typ`) Enforcement (`jws.nox`, `jwt.nox`):** Added `expected_typ` to `VerificationProfile` enforcing RFC 8725 §3.11 explicit typing to mitigate cross-JWT confusion attacks.
- **Signed Token Temporal & KeyRing Controls (`signed_token.nox`):** Added future `issued_at` rejection (`iat > now + leeway`), verified positive TTL and maximum TTL bounds, and added `verify_with_keyring()` for multi-tenant key resolution.
- **RSA 2048-bit Modulus Size Enforcement (`jwk.nox`):** Enforces minimum 2048-bit (256 bytes) modulus length using Base64URL character length check (`len(self.n) >= 342`, RFC 7518 §3.3), avoiding false positives from NOX's C-string NUL-byte dropping behavior.
- **Package Entry & Facade Alignment (`nox.json`):** Set package entry to `"cipher.nox"`.
- **Consumer Integration Suite (`tests/consumer_test.nox`):** Added end-to-end integration test proving external consumers importing `from cipher import ...` can sign, verify, and manage keys without issues.

## [1.0.0] - 2026-11-10

### Added
- **Production Stable Release (`v1.0.0`):** Complete, fully verified cryptographic tokens and key lifecycle library for the NOX ecosystem.
- **Unified Public Module (`cipher.nox`):** Clean, ergonomic exports covering all parsing, signing, verifying, and key management capabilities.
- **Sentinel Architecture Boundary Proof (`examples/sentinel_adapter.nox`, `tests/sentinel_boundary_test.nox`):** Verified separation invariant: Valid cryptographic signature does not imply authorization; Sentinel enforces access control policy independently.
- **Comprehensive Benchmarks (`benchmarks/benchmark_jws.nox`):** Sub-millisecond performance (>150,000 ops/sec) for compact JWS signing and verification.
- **Documentation Set:** Architecture guide, algorithms specification, key management runbooks, threat model, and security review evidence.
- **Full Test Suite:** 13 test suites (`13 passed, 0 failed`) with 100% pass rate across Ubuntu, macOS, and Windows CI matrix.

## [0.5.0] - 2026-11-10

### Added
- **Secure Remote JWKS Discovery (`jwks.nox`):** Configured HTTPS JWKS key discovery with strict SSRF defenses against localhost, loopback, private IPv4 ranges (RFC 1918), and cloud metadata endpoints.
- **Resilient Bounded Caching:** TTL-bounded cache management with outage grace windows (`stale_grace_sec`) preventing service disruption during remote provider downtime.
- **Negative Caching & Fetch Storm Mitigation:** Automatic negative caching for non-existent `kid` requests to prevent attacker-driven fetch storms.

## [0.4.0] - 2026-11-10

### Added
- **Key Reference & Lifecycle State Machine (`keys.nox`):** Five-state lifecycle (`PREPARED`, `ACTIVE_SIGNING`, `VERIFY_ONLY`, `RETIRED`, `REVOKED`) with terminal revocation protection and invalid transition enforcement.
- **KeyRing Management (`keyring.nox`):** Tenant/service isolation via `trust_domain`, duplicate `kid` prevention (`AmbiguousKeyError`), single active signer invariant per algorithm, and safe verification lookup.
- **Atomic Rotation Engine & Audit Receipts (`rotation.nox`):** Zero-downtime rotation with bounded overlap windows (`RotationReceipt`), enabling seamless token verification while rolling forward signing keys.
- **Immediate Revocation:** Immediate fail-closed rejection of compromised keys without delay.

## [0.3.0] - 2026-11-10

### Added
- **JSON Web Key (JWK) Standard Model (`jwk.nox`):** RFC 7517 compliant key model supporting RSA and symmetric octet keys (`kty`, `kid`, `alg`, `use`, `n`, `e`, `d`, `k`). Strict 2048-bit minimum key size enforcement.
- **Private Key Leakage Prevention:** `to_public_json()` enforces zero-leakage invariant, stripping all private exponents (`d`) and refusing public export of symmetric keys.
- **RFC 7638 SHA-256 Thumbprints:** Deterministic lexicographically-sorted thumbprint computation verified against official RFC 7638 Section 3.1 test vectors (`NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs`).
- **Algorithm Confusion Mitigation:** Verified immunity against public-key-as-symmetric-secret downgrade attacks.

## [0.2.0] - 2026-11-10

### Added
- **JWT Claims Engine (`claims.nox`):** RFC 7519 and RFC 8725 compliant claims parser and validator. Strict temporal boundaries for `exp` (expiration), `nbf` (not before), and `iat` (issued at). Clock leeway tolerance, future timestamp rejection, and max token age enforcement. Exact string match for `iss` (issuer) and string/array matching for `aud` (audience).
- **JWT Verification & Typing (`jwt.nox`):** `VerifiedJwt` evidence type for authenticated payloads and strictly isolated `UnverifiedJwt` for diagnostic and debugging use. `JwtIssuer` and `JwtVerifier` high-level engines.
- **Purpose-Bound Signed Opaque Tokens (`signed_token.nox`):** Domain-separated, lightweight opaque tokens (`cip_opk_v1` prefix) with purpose binding and TTL constraints preventing cross-purpose token substitution.

## [0.1.0] - 2026-11-10

### Added
- **Phase 0:** Platform validation, toolchain verification, cross-platform GitHub Actions CI and Release Gate workflows.
- **Errors Hierarchy (`errors.nox`):** Comprehensive, strongly-typed `CipherError` hierarchy separating format, crypto, claims, and provider errors without leaking sensitive materials.
- **Strict Base64URL (`encoding.nox`):** RFC 4648 §5 and RFC 7515 §2 compliance (unpadded, whitespace/padding/invalid character rejection).
- **Strict JSON Parser (`json_strict.nox`):** RFC 8725 §3.10 duplicate key rejection, bounded 64KB sizes, and type-checked accessors.
- **Cryptographic Provider Abstraction (`provider.nox`):** `CryptoProvider` interface and `DefaultCryptoProvider` backed by verified OS entropy and `nox.crypto.hmac_sha256`. Minimum 32-byte (256-bit) secret enforcement.
- **Compact JWS Engine (`jws.nox`):** Standards-compliant JWS signing and verification over exact ASCII bytes with unconditional `alg=none` rejection, `crit` and `b64=false` rejection, and verifier-controlled algorithm allowlists.
- **Official RFC 7515 Vectors & Negative Tests:** Official RFC 7515 Section A.1 test vector and exhaustive negative test suite covering tampered signatures, tampered payloads, algorithm downgrades, kid mismatches, and duplicate header members (`5 passed, 0 failed`).
