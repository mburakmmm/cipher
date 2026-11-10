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
- **`keyring.nox`**: Multi-tenant keyring with single-active-signer invariants and validate-before-commit atomic rollback.
- **`jwks.nox`**: Resilient remote JWKS discovery with SSRF defenses, bounded negative caching, and stale tolerance.

## 3. Resilience, SSRF & Atomic Rollback Invariants

### KeyRing Atomic Rollback
`KeyRing.rotate()` executes in two strictly distinct phases:
1. **Pre-commit Validation:** The incoming key's `trust_domain`, state, and uniqueness of `kid` are validated. Any mismatch or conflict raises typed exceptions immediately without mutating existing active signers.
2. **Commit Phase:** Only upon successful validation is the existing active signer transitioned to `VERIFY_ONLY` and the new key activated. This guarantees that signing services never experience downtime due to invalid rotation requests.

### SSRF & Negative Cache Boundaries
`is_safe_jwks_url()` enforces strict destination validation:
- Rejects non-HTTPS schemes unconditionally.
- Rejects all loopback addresses (`127.0.0.0/8`, `::1`, `localhost`, `0.0.0.0`).
- Rejects link-local and cloud metadata (`169.254.0.0/16`, `fe80::`, metadata endpoints).
- Rejects RFC 6598 CGNAT (`100.64.0.0/10`) and RFC 2544 Benchmark (`198.18.0.0/15`).
- Rejects full IPv6 ULA (`fc00::/7`), link-local (`fe80::/10`), and IPv4-mapped IPv6.
- Enforces DNS Pinning and redirect chain re-validation on all external HTTP transport adapters to prevent TOCTOU DNS rebinding SSRF.

- Rejects all RFC 1918 private IPv4 ranges (`10.0.0.0/8`, `192.168.0.0/16`, and all 16 subnets of `172.16.0.0/12`).
- Negative cache is bounded by `MAX_NEGATIVE_CACHE_ENTRIES` (256) with FIFO eviction, preventing memory exhaustion attacks under random `kid` floods.
- Note on transport: Full socket pinning and DNS rebinding protections belong to NOX's common HTTP transport layer when remote HTTP fetching is integrated.
