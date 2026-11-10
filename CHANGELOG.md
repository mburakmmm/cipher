# Changelog

All notable changes to Cipher will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-10

### Added
- **Phase 0:** Platform validation, toolchain verification, cross-platform GitHub Actions CI and Release Gate workflows.
- **Errors Hierarchy (`errors.nox`):** Comprehensive, strongly-typed `CipherError` hierarchy separating format, crypto, claims, and provider errors without leaking sensitive materials.
- **Strict Base64URL (`encoding.nox`):** RFC 4648 §5 and RFC 7515 §2 compliance (unpadded, whitespace/padding/invalid character rejection).
- **Strict JSON Parser (`json_strict.nox`):** RFC 8725 §3.10 duplicate key rejection, bounded 64KB sizes, and type-checked accessors.
- **Cryptographic Provider Abstraction (`provider.nox`):** `CryptoProvider` interface and `DefaultCryptoProvider` backed by verified OS entropy and `nox.crypto.hmac_sha256`. Minimum 32-byte (256-bit) secret enforcement.
- **Compact JWS Engine (`jws.nox`):** Standards-compliant JWS signing and verification over exact ASCII bytes with unconditional `alg=none` rejection, `crit` and `b64=false` rejection, and verifier-controlled algorithm allowlists.
- **Official RFC 7515 Vectors & Negative Tests:** Official RFC 7515 Section A.1 test vector and exhaustive negative test suite covering tampered signatures, tampered payloads, algorithm downgrades, kid mismatches, and duplicate header members (`5 passed, 0 failed`).
