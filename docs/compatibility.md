# Platform and NOX Compatibility Report

- **Date:** 2026-11-19
- **Compiler:** `noxc 2.2.38`
- **Platform:** macOS Darwin arm64 (Apple Silicon), Linux x86_64/arm64, Windows x86_64
- **Toolchain backend:** LLVM (default hosted), QBE (secondary / freestanding supported)

## Verified NOX Commands

```bash
noxc version                         # noxc 2.2.38
noxc check <file>
noxc check --strict-spawn-shared     # M:N shared-mutation lint
noxc check --profile freestanding    # freestanding capability boundary check
noxc test                            # runs *_test.nox
noxc fmt <file>
noxc run <file>
noxc bindgen <header.h> --lib <lib>  # C header FFI binding generator
noxc explain [--release] <file>      # ARC / stack / arena allocation diagnostics
```

## Available Standard Library Crypto & Security Capabilities

From `~/.nox-lang/lib/nox/stdlib/nox/crypto.nox`:
- `nox.crypto.sha256(data: str) -> str`
- `nox.crypto.sha384(data: str) -> str`
- `nox.crypto.sha512(data: str) -> str`
- `nox.crypto.sha3_256(data: str) -> str`
- `nox.crypto.sha3_512(data: str) -> str`
- `nox.crypto.blake3(data: str) -> str`
- `nox.crypto.hmac_sha256(key: str, data: str) -> str`
- `nox.crypto.constant_time_eq(a: str, b: str) -> bool`
- `nox.crypto.secure_random_hex(n_bytes: int) -> str` (`@capability.requires("entropy")`)

From `~/.nox-lang/lib/nox/stdlib/nox/ed25519.nox`:
- `nox.ed25519.verify(pub_hex: str, msg: str, sig_hex: str) -> bool` (Zig `std.crypto.sign.Ed25519`)
- `nox.ed25519.fingerprint(pub_hex: str) -> str`

From `~/.nox-lang/lib/nox/stdlib/nox/base64.nox`, `nox/atomic.nox`, `nox/time.nox`, `nox/json.nox`, `nox/mem.nox`, `nox/property.nox`, `nox/tls.nox`:
- `nox.base64.encode_url(data: str) -> str`, `nox.base64.decode(data: str) -> str`
- `nox.atomic.AtomicRef` (`new_ref`, `from_ref_handle`, `get`, `set`, `version`, `free`) alongside `AtomicInt` / `AtomicBool`
- `nox.time.monotonic_ns() -> int`, `now_ns() -> int`, `boot_ms() -> int` (`@capability.requires("clock")`)
- `nox.json`: Tape-backed lazy `JsonValue` (`object_len`, `object_key`, `object_value`, `array_len`, `array_get`, `get`) preserving strict RFC 8725 duplicate-key rejection
- `nox.mem.stats() -> MemStats` (`allocations`, `frees`, `live`, `bytes_allocated`)
- `nox.property`: Seeded shrinking property-based test runner (`Rng`, `check`, `replay`)
- `nox.tls`: Pure Zig `std.crypto.tls` client (`TlsStream.connect(host, port)`)

## Architecture & Security Decisions

1. **Strict Base64URL:** `nox.base64.decode` handles standard and URL-safe base64, so `encoding.nox` enforces strict RFC 7515 Section 2 syntax (rejects padding `=`, `+`, `/`, whitespace) before decoding.
2. **Duplicate JSON Keys (RFC 8725 §3.10) & Lazy Tape Access:** `json_strict.nox` wraps `nox.json.parse` and `nox.json` tape accessors (`object_len`, `object_key`, `object_value`, `array_len`, `array_get`, `get`). `nox.yyjson` is **strictly forbidden** on security-critical paths because `yyjson` does not reject duplicate object keys.
3. **Pure-NOX `EdDSA` + Optional OpenSSL C Shim (`cipher.openssl_provider`):**
   - Core Cipher uses `nox.ed25519.verify` for zero-dependency EdDSA (Ed25519) verification + `OKP` JWK support across all desktop targets.
   - Because `nox.crypto` / `nox.ed25519` do not expose RSA (`RS256`/`PS256`), ECDSA (`ES256`), `HS384`/`HS512`, or Ed25519 signing, Cipher provides an **opt-in** OpenSSL `libcrypto` C shim (`native/cipher_openssl.h`, `native/cipher_openssl_shim.c`, `openssl_provider.nox`). Programs that do not import `cipher.openssl_provider` never link or require the C shim (`package source` compatibility preserved).
   - Inside `native/cipher_openssl_shim.c`, `libcrypto` is resolved via `dlopen` (avoiding unversioned `/usr/lib/libcrypto.dylib` on macOS SIP) / `LoadLibraryA` (Windows), enforcing OpenSSL `EVP` cryptography rather than homegrown primitives.
4. **NOX Byte/NUL Semantics across C FFI:** While NOX 2.1.186 strings preserve embedded `0x00` bytes in `nox.base64.decode`, `nox.bytes.str_from_list`, and `nox.strings.char_from_byte(0)`, C FFI `const char*` parameters stop at NUL (`\0`). Therefore, all keys, raw signatures, and outputs crossing `native/cipher_openssl_shim.c` are encoded strictly in ASCII hexadecimal (`0-9a-f`).
5. **Module Globals vs. Spawned OS Threads:** Multi-thread stress testing under `noxc 2.1.186` revealed that freshly spawned `nox.thread.start` OS threads can transiently observe zero-initialized module globals (`SHARED_KEY_WORDS`, `STATE_*`). Core `KeyRing` and `KeyRef` synchronization paths inline literal constants internally while keeping public exported module constants intact (`100/100` OS thread stress runs passing).
6. **Freestanding & WASM Targets:** Consistent with `AGENTS.md` §4 and `nox.crypto` (`bare_kernel`), targets lacking OS CSPRNG entropy (`--profile freestanding`) must never claim cryptographic key generation or production token security (`noxc check --profile freestanding cipher.nox` fails closed on capability-restricted imports).
