# Architecture & Design — Cipher

## 1. System Overview

Cipher is a framework-independent, pure NOX cryptographic token and contract library. It provides high-performance, strictly verified implementations of JWS (RFC 7515), JWT claims validation (RFC 7519), JWK (RFC 7517 / RFC 7638), purpose-bound signed tokens, and key lifecycle management.

```
       Consumers: Nyx / Aether / Aura / Sentinel / Applications
                                  │
               cipher.nox (Unified Public Interface)
                                  │
     ┌────────────────────────────┼────────────────────────────┐
     │                            │                            │
     ▼                            ▼                            ▼
[ Compact JWS ]            [ JWT Claims ]              [ Signed Tokens ]
  RFC 7515                   RFC 7519                    itsdangerous
  Strict ASCII verify        Temporal boundaries         Purpose-bound
  ProtectedHeader            Audience / Issuer           Domain separation
     │                            │                            │
     └────────────────────────────┼────────────────────────────┘
                                  │
                                  ▼
                     [ KeyRing & Key Lifecycle ]
                       PREPARED -> ACTIVE_SIGNING -> VERIFY_ONLY -> RETIRED / REVOKED
                       Atomic rotation with bounded overlap
                       Trust domain isolation
                                  │
                                  ▼
                     [ CryptoProvider Abstraction ]
                       OS CSPRNG (@capability.requires("entropy"))
                       Verified HMAC-SHA256 & Constant-time MAC checks
```

## 2. Component Structure

- **`errors.nox`**: Comprehensive strongly-typed exception hierarchy rooted in `CipherError`. No sensitive parameters or secrets in exception strings.
- **`encoding.nox`**: RFC 4648 §5 URL-safe base64 encoding/decoding rejecting padding (`=`), whitespace, and non-alphabet characters. Hex conversion utilities.
- **`json_strict.nox`**: RFC 8725 §3.10 duplicate key rejection, bounded sizes, and strongly-typed value accessors.
- **`provider.nox`**: Pluggable provider abstraction with `DefaultCryptoProvider` backed by OS CSPRNG.
- **`jws.nox`**: Compact JWS parsing, signing, and verification over original ASCII bytes with verifier-controlled algorithm allowlists.
- **`claims.nox`**: Numerical date verification (`exp`, `nbf`, `iat`), clock leeway, issuer exact match, audience string/array match.
- **`jwt.nox`**: Two-stage validation returning `VerifiedJwt` evidence. Separate `UnverifiedJwt` for diagnostic inspection.
- **`signed_token.nox`**: Domain-separated, purpose-bound tokens (`cip_opk_v1`) preventing cross-purpose token substitution.
- **`jwk.nox`**: RFC 7517 JWK model, private key leakage protection, and RFC 7638 SHA-256 thumbprints.
- **`keys.nox` & `rotation.nox`**: Key lifecycle state machine and audit rotation receipts.
- **`keyring.nox`**: Multi-tenant keyring with single-active-signer invariants.
- **`jwks.nox`**: Resilient remote JWKS discovery with SSRF defenses, negative caching, and stale tolerance.
