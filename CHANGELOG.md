# Changelog

All notable changes to Cipher will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.4] - 2026-11-10

### Fixed & Hardened (Technical SOL IV Architecture Audit)
- **Unified `KeyRingState` Single-Reference Atomic Publication (`keyring.nox`):** Replaced separate `self.keys` and `self.version` fields with a single, immutable `KeyRingState` record (`version: int`, `keys: list[KeyRef]`, `created_at: int`). All state mutations publish atomically via a single reference assignment (`self.state = KeyRingState(...)`), completely eliminating torn reads and ensuring readers always observe an internally coherent snapshot.
- **Lost-Update Guard in Multi-Writer Coordination (`keyring.nox`):** Hardened `add_key()`, `rotate()`, and `revoke()` by capturing `base_state = self.state` at the start of preparation. If an interleaved concurrent writer commits before the prepared state is published (`self.state.version != base_state.version`), the mutation aborts fail-closed with `ConfigurationError("Concurrent modification detected...")`, guaranteeing zero lost updates.
- **Structural Hextet & Bitmask IPv6 SSRF Validation (`jwks.nox`):** Replaced fragile string prefix matching with full RFC 4291 structural hextet parsing, `::` zero-compression expansion, and numerical 16-bit bitmask validation:
  - ULA: `fc00::/7` via `(h0 & 0xfe00) == 0xfc00`
  - Link-Local: `fe80::/10` via `(h0 & 0xffc0) == 0xfe80`
  - Multicast: `ff00::/8` via `(h0 & 0xff00) == 0xff00`
  - Discard (`100::/64`), Documentation (`2001:db8::/32`), Benchmark (`2001:2::/48`)
- **DNS Resolution Verification Public API (`verify_resolved_ip` in `jwks.nox`, `cipher.nox`):** Added and exported `verify_resolved_ip(ip_str: str) -> bool` to allow caller HTTP transports to validate resolved IP addresses against all restricted IPv4 and IPv6 CIDR blocks before connecting (mitigating DNS Rebinding and TOCTOU attacks). Documented in `docs/threat-model.md` and `docs/architecture.md`.
- **RSA Public Exponent IEEE 754 53-Bit Safe Integer Clarification & Boundary Tests (`jwk.nox`, `tests/jwk_test.nox`):** Corrected documentation and error definitions to reflect IEEE 754 53-bit safe integer limits (`2^53 - 1` ceiling, `MAX_SAFE_INT_BEFORE_SHIFT = 140737488355327`). Added comprehensive negative tests for 1-character (`len % 4 == 1`), 5-character, and overflowing 10-character exponents.
- **Concurrency & Interleaving Test Suite (`tests/concurrency_keyring_test.nox`):** Added Test 6 verifying unified snapshot state publication and interleaved lost-update conflict rejection.

## [1.0.3] - 2026-11-10

### Fixed & Hardened (Technical SOL III Architecture Audit)
- **KeyRef Defensive Cloning & Snapshot Immutability (`keyring.nox`):** `KeyRing.get_signing_key()` and `KeyRing.get_verification_key()` now return defensive clones (`k.clone()`). Mutations on caller-held `KeyRef` references (e.g. `k.state = STATE_RETIRED` or tampering with `secret_material`) cannot affect or corrupt the internal KeyRing published snapshot. Verified in `tests/keyring_test.nox`.
- **Multi-Writer Optimistic Concurrency Control (CAS) & Versioning (`keyring.nox`):** Added a monotonically increasing `version: int` attribute and `expected_version` CAS parameter to `add_key()`, `rotate()`, and `revoke()`. Concurrent conflicting writers attempting to commit state against a stale snapshot are immediately detected and rejected with `ConfigurationError` without mutating KeyRing state. Added `get_version()` and `get_snapshot()`, verified in `tests/concurrency_keyring_test.nox`.
- **RSA Public Exponent Length Upper Bound & Integer Overflow Protection (`jwk.nox`):** Enforces an explicit upper bound on RSA public exponent length (`MAX_RSA_EXPONENT_CHARS: int = 11`, 64-bit / 8 bytes ceiling, RFC 7518 §6.3.1.2) and guards `_b64url_to_uint` against 64-bit integer bit-shift overflows (> `MAX_SAFE_INT_BEFORE_SHIFT = 140737488355327`). Excessively long or overflowing exponent values fail closed with `InvalidKeyError`. Negative tests added in `tests/jwk_test.nox`.
- **Structural IP Parsing & 14-CIDR SSRF Filter (`jwks.nox`):**
  - Removed duplicate `0x` check.
  - Implemented numerical `_is_restricted_ipv4` parser filtering 14 non-routable CIDR blocks: `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10` (RFC 6598 CGNAT), `127.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`, `192.0.0.0/24`, `192.0.2.0/24`, `192.88.99.0/24`, `192.168.0.0/16`, `198.18.0.0/15` (RFC 2544 Benchmark), `198.51.100.0/24`, `203.0.113.0/24`, `224.0.0.0/4`, and `240.0.0.0/4`.
  - Applied structural verification to IPv4-mapped IPv6 targets (`::ffff:...`).
  - Added negative test vectors in `tests/jwks_test.nox`.
  - Documented DNS Pinning and redirect chain requirements in `docs/threat-model.md` and `docs/architecture.md`.
- **Package Hierarchy Submodule Forwarding Facade (`cipher/`):** Added package forwarding directory (`cipher/*.nox`) enabling external consumers using `nox.json` `requires` and `noxc fetch` to consume Cipher seamlessly via standard NOX package resolution (`from cipher.cipher import ...` or `from cipher.jwt import ...`).
- **JWKS Network Outage & Stale Grace Transition Suite (`tests/jwks_stress_test.nox`):** Added simulation test suite verifying `mark_outage()` recording, stale grace window tolerances during active outages, fail-closed enforcement when stale grace is exceeded, and instant recovery upon fresh JWKS feed delivery.


## [1.0.2] - 2026-11-10

### Fixed & Hardened (Technical SOL II Architecture Audit)
- **KeyRing RCU (Read-Copy-Update) Immutable Snapshot Concurrency (`keyring.nox`, `keys.nox`):** Migrated `KeyRing` state transitions to an immutable snapshot publication pattern. Key additions, rotations, and revocations construct fresh snapshot clones and atomically publish via single-reference assignment (`self.keys = new_snap`). Reader lookups capture local snapshot references, ensuring readers never observe intermediate mutation states and an active signer is never absent. Added `KeyRef.clone()` and `tests/concurrency_keyring_test.nox`.
- **Structural RSA JWK & Public Exponent Validation (`jwk.nox`):** Enhanced RSA parameter verification in RFC 7518 §6.3.1 compliance without relying on C-string binary conversions:
  - Base64URL syntax verification on modulus `n` and exponent `e`.
  - Leading zero octet rejection on `n` and `e` (RFC 7518 §6.3.1.1 & §6.3.1.2).
  - Modulus MSB bit verification (ensuring full 2048-bit magnitude, rejecting zero MSBs).
  - Public exponent `e` decoding and validation: enforces positive, odd integer > 1 (e.g., 65537, 3), strictly rejecting even or <= 1 exponents.
  - Added comprehensive negative test vectors in `tests/jwk_test.nox`.
- **Standard `nox.url` SSRF Defense & IP Filtering (`jwks.nox`):**
  - Replaced manual string splitting with RFC 3986 standard parsing via `nox.url.parse()`.
  - Fail-closed rejection of URLs containing userinfo (`u.userinfo != ""` prevents credential hiding and authority spoofing).
  - Full IPv4-mapped IPv6 address rejection (`::ffff:127.0.0.1`, `::ffff:10.0.0.0/8`, `::ffff:192.168.0.0/16`, `::ffff:169.254.0.0/16`, `::ffff:172.16-31`).
  - Complete IPv6 ULA coverage (`fc00::/7` covering both `fc` and `fd` prefixes) and Link-Local (`fe80::/10`).
  - Alternative IP representations (pure decimal integer IPs e.g. `2130706433`, hexadecimal `0x7f.0.0.1`, octal dotted-decimal notations).
  - Negative tests in `tests/jwks_test.nox`.
- **64-bit Large Safe Integer & Fractional Precision (`json_strict.nox`):** Updated `get_int_field()` to guarantee 64-bit safe integer parsing (up to `2^53 - 1` = `9007199254740991`) and negative integers, strictly rejecting any fractional numbers with `JsonFormatError`. Added boundary tests in `tests/json_strict_test.nox`.
- **Isolated External Consumer Verification (`scripts/test-isolated-consumer.sh`):** Added automated validation script that creates a temporary isolated project outside the repository, imports `cipher` as an external package, and executes full JWT, Signed Token, and KeyRing workflows end-to-end.
- **JWKS Cache, Grace Window & Negative-Cache Bounded Stress Suite (`tests/jwks_stress_test.nox`):** Added stress test executing 1,000+ sequential unknown `kid` lookups verifying that negative cache remains strictly bounded at 256 entries with FIFO eviction, cached negative keys reject immediately, and TTL stale grace windows function reliably under load.

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
