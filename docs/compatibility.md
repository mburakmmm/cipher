# Platform and NOX Compatibility Report

- **Date:** 2026-11-10
- **Compiler:** `noxc 2.1.0`
- **Platform:** macOS Darwin arm64 (Apple Silicon)
- **Toolchain backend:** LLVM (default hosted), QBE (secondary supported)

## Verified NOX Commands

```bash
noxc --version   # noxc 2.1.0
noxc check <file>
noxc test        # runs *_test.nox
noxc fmt <file>
noxc run <file>
```

## Available Standard Library Crypto Capabilities

From `~/.nox-lang/lib/nox/stdlib/nox/crypto.nox`:
- `nox.crypto.sha256(data: str) -> str`
- `nox.crypto.sha512(data: str) -> str`
- `nox.crypto.hmac_sha256(key: str, data: str) -> str`
- `nox.crypto.constant_time_eq(a: str, b: str) -> bool`
- `nox.crypto.secure_random_hex(n_bytes: int) -> str`

From `~/.nox-lang/lib/nox/stdlib/nox/base64.nox`:
- `nox.base64.encode_url(data: str) -> str`
- `nox.base64.decode(data: str) -> str`

## Architecture Gaps & Implementation Strategy

1. **Strict Base64URL:** `nox.base64.decode` handles standard and URL-safe base64, but strict RFC 7515 Section 2 requires rejecting padding (`=`), whitespace, and non-alphabet characters. Cipher will implement a strict parser wrapper in `encoding.nox`.
2. **Duplicate JSON Keys:** Sıkı duplicate key reddi (RFC 8725 Section 3.10) için `json_strict.nox` modülü geliştirilecektir.
3. **Asymmetric Crypto (RS256):** Standard library currently focuses on symmetric hashes (SHA256, SHA512, HMAC-SHA256, Argon2, bcrypt, scrypt). RS256/asymmetric verification will be verified and designed in Phase 3.
