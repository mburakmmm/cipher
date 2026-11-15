# Supported Cryptographic Algorithms — Cipher

| Algorithm | RFC | Key Type | Minimum Key Size | Status & Security Profile |
|---|---|---|---|---|
| **HS256** | RFC 7518 §3.2 | Symmetric (`oct`) | 256 bits (32 bytes) | **Production Active (Pure NOX)**: Verified against RFC 7515 A.1 vectors; constant-time MAC checks (`nox.crypto.constant_time_eq`) |
| **HS384** | RFC 7518 §3.2 | Symmetric (`oct`) | 384 bits (48 bytes) | **Production Active (Opt-In `cipher.openssl_provider`)**: OpenSSL `HMAC(EVP_sha384())` + constant-time hex comparison |
| **HS512** | RFC 7518 §3.2 | Symmetric (`oct`) | 512 bits (64 bytes) | **Production Active (Opt-In `cipher.openssl_provider`)**: OpenSSL `HMAC(EVP_sha512())` + constant-time hex comparison |
| **EdDSA (`Ed25519`)** | RFC 8037 §3.1 | Asymmetric (`OKP` `Ed25519`) | 256 bits (32 bytes raw key, 64 bytes sig) | **Production Active**: Zero-dependency pure-NOX verification (`nox.ed25519.verify`) in `DefaultCryptoProvider`; full sign + verify in `OpenSslCryptoProvider`; RFC 8037 Appendix A.4 tested |
| **RS256** | RFC 7518 §3.3 | Asymmetric (`RSA`) | 2048 bits (342 Base64URL chars / 256 bytes) | **Production Active (Opt-In `cipher.openssl_provider`)**: OpenSSL PKCS#1 v1.5 SHA-256 sign/verify + JWK/PEM support + `<2048`-bit rejection |
| **PS256** | RFC 7518 §3.5 | Asymmetric (`RSA`) | 2048 bits (saltLen = 32) | **Production Active (Opt-In `cipher.openssl_provider`)**: OpenSSL RSA-PSS SHA-256 / MGF1-SHA256 + strict padding confusion rejection vs `RS256` |
| **ES256** | RFC 7518 §3.4 | Asymmetric (`EC` `P-256`) | 256 bits (32-byte `x`/`y`, exact 64-byte raw `R \|\| S`) | **Production Active (Opt-In `cipher.openssl_provider`)**: OpenSSL P-256 ECDSA sign/verify + strict canonical raw `R \|\| S` <-> ASN.1 DER conversion |
| **none** | RFC 7518 §3.6 | None | N/A | **Unconditionally Rejected** (`DisallowedAlgorithmError`) |

## Security Invariants

1. **Algorithm Allowlist (Verifier-Controlled):**
   The verification algorithm is dictated exclusively by `VerificationProfile.allowed_algs`. An attacker cannot alter trust paths by modifying the token's `alg` header.
2. **Algorithm & Key Confusion Immunity:**
   Symmetric secrets and asymmetric keys/curves use incompatible allowlist families (`oct` vs `OKP/Ed25519` vs `RSA` vs `EC/P-256`). Passing an HMAC secret to `RS256`/`ES256`/`EdDSA`, a PEM public key to `HS256`, or a `RS256` signature to `PS256` fails closed immediately.
3. **Key Length & Format Enforcement:**
   - `HS256` secrets must be >= 32 bytes; `HS384` >= 48 bytes; `HS512` >= 64 bytes.
   - RSA keys must have a modulus bit length >= 2048 bits (both JWK and OpenSSL EVP runtime checks).
   - `ES256` JOSE signatures must be exact 64-byte raw `R || S` (128 hex chars); DER signatures passed directly as compact JWS signatures are rejected.
   - `EdDSA` keys and signatures enforce exact 32-byte keys (64 hex chars) and 64-byte signatures with NUL-byte-safe hexadecimal encoding across C FFI boundaries.
4. **Explicit Typing (`typ`):**
   When `VerificationProfile.expected_typ` is set, headers must strictly match the declared token type (RFC 8725 §3.11).
