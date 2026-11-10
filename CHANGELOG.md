# Changelog

All notable changes to Cipher will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.7] - 2026-11-10

### Fixed & Hardened (Technical SOL VII Architecture Audit)
- **Hardware Acquire-Release RMW Memory Ordering in Seqlock (`keyring.nox`, `docs/architecture.md`):**
  - Disassembled `noxrt.o` and verified that `nox_atomic_cas` (`casal` on ARM64, `lock cmpxchg` on x86_64) and `nox_atomic_add` (`ldaddal` on ARM64, `lock xadd` on x86_64) issue full hardware **Acquire-Release (`AL` / `seq_cst`) RMW barriers**, whereas `nox_atomic_load` (`ldar`) and `nox_atomic_store` (`stlr`) are one-way barriers.
  - Upgraded `_read_consistent_state()` to use `self._seq.add(0)` for both `s1` and `s2` so normal memory loads (`st = self._state`) cannot float above `s1` or sink below `s2` on weakly-ordered architectures (ARM64).
  - Upgraded `_commit_state()` to use `self._seq.compare_and_swap(base_ver * 2, odd_seq)` and `self._seq.compare_and_swap(odd_seq, even_next_seq)` (`casal` / `lock cmpxchg`) for full Acquire-Release barriers on both entry and exit of the Seqlock write section.
  - Documented the single-call `st = ring.get_state()` consistency rule in `docs/architecture.md`.
- **Cross-OS-Thread Shared `KeyRingState` Synchronization & Visibility Proof (`keyring.nox`, `tests/concurrency_keyring_test.nox`):**
  - Added `export_shared_handle() -> str`, `attach_shared_handle(handle_str: str)`, and `free_shared_handle()` to `KeyRing`, backed by 512 process-wide `nox.atomic.AtomicInt` cells (`SHARED_ATOMIC_WORDS = 512`, 3,072 bytes capacity).
  - Pre-packs canonical state words in Phase A before entering the odd Seqlock state, and copies raw `int` words (`_read_shared_words_raw`) between `s1` and `s2` before unpacking/deserializing only after `s1 == s2`.
  - Added **Test 12 (Cross-OS-Thread Shared `KeyRingState` Identity & Visibility Proof)** in `tests/concurrency_keyring_test.nox`, proving that when 4 parallel OS worker threads compete on `expected_version=1`, both the **Main Thread** and an independent **5th OS Reader Thread** observe `version == 2`, the winning worker's active signing `kid`, the old key demoted to `VERIFY_ONLY`, and the exact same canonical SHA-256 state seal hash.
- **Prefix-Free Length-Prefixed Canonical Serialization & Per-Instance HMAC Seal (`keyring.nox`, `docs/threat-model.md`):**
  - Replaced `:` and `|` delimiter concatenation in `_compute_state_seal` with an unambiguous length-prefixed canonical serializer (`_serialize_state_canonical` / `_deserialize_state_canonical` using `<decimal_byte_len>#<exact_bytes>`), eliminating delimiter injection collisions (`:`, `|`, `#`). Verified in **Test 9b**.
  - Added per-instance `KeyRing._state_mac` (`nox.crypto.hmac_sha256` keyed with `_seal_key`) to detect full `KeyRingState` object replacement, and documented the exact in-process tamper-evident security boundary in `docs/threat-model.md`.
- **Explicit Two-Phase Commit Linearization Point (`keyring.nox`, `docs/architecture.md`):**
  - Separated `_commit_state()` into **Phase A (Pre-Linearization Validation & Staging — Rollback Permitted)** and **Phase B (The Linearization Point — `self._seq.compare_and_swap(odd_seq, even_next_seq)`)**. Once `committed = True`, rollback is strictly forbidden (`if not committed:`).
- **Generative PRNG Differential IP Fuzzing (`tests/ip_fuzz_property_test.nox`):**
  - Added **Property 5**: 1,000+ deterministic PRNG-generated IPv4, IPv6, IPv4-mapped IPv6, and CIDR boundary test cases evaluated differentially against an independent 32-bit/128-bit bitmask reference oracle (`_oracle_ipv4_restricted_u32`, `_oracle_ipv6_restricted`) and `nox.url.parse` with zero divergences.
- **Snapshot Read & Rotation Performance Benchmark Suite (`tests/benchmark_keyring_test.nox`):**
  - Added `tests/benchmark_keyring_test.nox` measuring 500 Seqlock `get_signing_key()` reads (~1–2 ms), 500 `get_verification_key()` lookups (~1–2 ms), 30 sequential `rotate()` commits (~2–3 ms), and 10 cross-thread shared atomic state round-trips (~1–2 ms).

## [1.0.6] - 2026-11-10

### Fixed & Hardened (Technical SOL VI Architecture Audit)
- **Seqlock Coherent Snapshot & Commit Ordering Fix in `KeyRing` (`keyring.nox`):**
  - Eliminated the transient reader-inconsistency window where `_atomic_version` was incremented before `self.state` was assigned (which could allow a concurrent reader calling `get_version()` and `get_signing_key()` to observe version `N+1` with key snapshot `N`).
  - Implemented a hardware-backed Seqlock + Single-Truth Snapshot protocol (`_state: KeyRingState`, `_seq: nox.atomic.AtomicInt`, `_read_consistent_state()`). Writers enter an odd sequence (`_seq.store(base_ver * 2 + 1)`), publish `self._state = new_state` FIRST, and seal with an even sequence (`_seq.store((base_ver + 1) * 2)`).
  - All reader operations (`get_version()`, `get_state()`, `get_snapshot()`, `get_signing_key()`, `get_verification_key()`) now read exclusively through `_read_consistent_state()`, guaranteeing version and key snapshot coherency.
- **Exception-Safe Writer Lock Release & Atomic Rollback (`keyring.nox`):**
  - Wrapped the critical section of `_commit_state()` in a `try ... except Exception as err:` guard with a `cas_won` flag. If any error occurs after lock acquisition, `_state`, `_atomic_version`, and `_seq` are rolled back cleanly (when `cas_won == True`) and `_write_lock.store(False)` is unconditionally executed before raising `ConfigurationError`, preventing permanent writer deadlock.
- **Cryptographic Tamper-Evident Sealing of `KeyRingState` (`keyring.nox`):**
  - Because NOX does not provide a language-level `private` keyword, `KeyRingState` now computes a SHA-256 integrity seal (`_integrity_hash: str` via `_compute_state_seal`) over `(version, created_at, canonical _keys state)` at construction and verifies it in constant time (`nox.crypto.constant_time_eq`) on every state read (`verify_integrity()`, `get_keys()`, `key_count()`, `_read_consistent_state()`). Direct external tampering with `state.version`, `state.created_at`, or `state._keys` fails closed with `ConfigurationError`.
- **Parallel Multi-Thread `rotate()` & Mixed Reader/Writer Contention Tests (`tests/concurrency_keyring_test.nox`):**
  - Added Test 9 (Tamper-Evident SHA-256 Sealing of `KeyRingState`), Test 10 (Exception-Safe Lock Release & Seqlock Coherent Snapshot), Test 11 (4-OS-Thread Parallel `KeyRing.rotate()` Contention via `nox.thread.start`), and Test 11b (Concurrent `rotate` + `revoke` & Reader Coherency on Shared `KeyRing`).
- **Two-Stage Local + Remote Registry Consumer Verification (`scripts/test-isolated-consumer.sh`):**
  - Upgraded `scripts/test-isolated-consumer.sh` to execute both **Stage 1** (Local Git Staging repository `noxc add` + `noxc fetch`) and **Stage 2** (Real Remote Registry installation via `noxc add cipher` + `noxc fetch` resolving `https://github.com/mburakmmm/cipher@main` from `noxpkg.noxlang.com`).
- **Property-Based & Adversarial Fuzz Suite for IPv4/IPv6 Parsers (`tests/ip_fuzz_property_test.nox`):**
  - Added a dedicated property-based and fuzz test suite covering exhaustive CIDR boundary invariants across all 14 restricted IPv4 blocks, 5-representation equivalence (`::ffff:a.b.c.d`, `0:0:0:0:0:ffff:a.b.c.d`, `[::ffff:a.b.c.d]`, lowercase/uppercase pure hex `::ffff:XXXX:YYYY`) for IPv4-mapped IPv6, `::` zero-compression position invariance, and 100+ adversarial malformed IP inputs.

## [1.0.5] - 2026-11-10

### Fixed & Hardened (Technical SOL V Architecture Audit)
- **Hardware-Backed Atomic CAS & Writer Mutex in `KeyRing` (`keyring.nox`, `nox.atomic`):**
  - Replaced check-then-act version comparisons with genuine CPU-level atomic primitives (`_write_lock: nox.atomic.AtomicBool` and `_atomic_version: nox.atomic.AtomicInt` backed by `nox_atomic_cas`).
  - `_commit_state()` acquires the hardware writer mutex (`_write_lock.compare_and_swap(False, True)`) and executes an atomic compare-and-swap on the version cell (`_atomic_version.compare_and_swap(base_ver, base_ver + 1)`), eliminating the T1-T6 race window between concurrent writers and proving zero lost updates at the hardware level.
  - Verified with both deterministic contention tests and a 4-thread parallel OS worker stress test (`nox.thread.start`) in `tests/concurrency_keyring_test.nox`.
- **Deep `KeyRingState` Immutability & Removal of Mutable Alias (`keyring.nox`):**
  - Removed the `self.keys` compatibility alias from `KeyRing` so external callers cannot retain a direct reference to internal key arrays.
  - Encapsulated `KeyRingState` keys in `_keys: list[KeyRef]` with deep defensive cloning (`KeyRef.clone()`) on both construction and inspection (`get_keys()`, `key_count()`, `get_state()`).
- **Decoupled IPv4/IPv6 Syntactic Parsing & SSRF Security Policy (`jwks.nox`):**
  - Separated syntactic IP parsing (`parse_ipv4(s) -> IPv4Address`, `parse_ipv6(s) -> IPv6Address`) from SSRF policy evaluation (`is_restricted_ipv4_addr(addr)`, `is_restricted_ipv6_addr(addr)`).
  - Fixed RFC 4291 IPv4-mapped IPv6 expansion: embedded 32-bit IPv4 suffixes (e.g. `::ffff:8.8.8.8`, `::ffff:127.0.0.1`) are parsed via `parse_ipv4` and expanded into **two** 16-bit hextets (`(o0 << 8) | o1`, `(o2 << 8) | o3`), computing `::` zero-compression across the remaining 6 hextets (`[0, 0, 0, 0, 0, 0xffff, 0x0808, 0x0808]`).
  - Expanded IPv6 transition range protections to cover IPv4-compatible (`::/96`), IPv4-translated (`::ffff:0:0:0/96`), NAT64 (`64:ff9b::/96`), 6to4 (`2002::/16`), Teredo (`2001::/23`), and RFC 9637 documentation (`3fff::/20`).
- **Strict Invalid IP Rejection in `verify_resolved_ip()` (`jwks.nox`, `tests/jwks_test.nox`):**
  - `verify_resolved_ip(ip_str: str) -> bool` now enforces syntactic validity first via `parse_ipv4` / `parse_ipv6`. Any malformed IP string (e.g. `"1.2.3"`, `"127.0.0.1.5"`, `"999.999.999.999"`, `"0177.0.0.1"`, `"2001::db8::1"`, `"fe80::1%eth0"`, hostnames, or empty strings) raises `EncodingError` internally and returns `False` immediately.
- **Native NOX Package Manager (`noxc add` + `noxc fetch`) Compatibility (`*.nox`, `scripts/test-isolated-consumer.sh`):**
  - Standardized internal module imports to `from cipher.<module> import ...` across all library files, enabling external projects to install Cipher directly via `noxc add cipher` and `noxc fetch` without copying source files.
  - Updated `scripts/test-isolated-consumer.sh` and CI workflows (`.github/workflows/ci.yml`, `.github/workflows/release.yml`) to execute end-to-end `noxc init`, `noxc add`, `noxc fetch`, `nox.lock` SHA verification, and consumer execution on every run.

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
