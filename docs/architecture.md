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

### KeyRing Unified State, Seqlock Coherency, Tamper-Evident Sealing & Hardware Atomic CAS
`KeyRing` manages key lifecycle and rotation through a deeply immutable `KeyRingState` model backed by `nox.atomic` primitives and a Seqlock reader/writer protocol:
1. **Deeply Immutable & Tamper-Evident `KeyRingState`:** Internal keys are stored in `_keys: list[KeyRef]` with defensive cloning on both construction and inspection (`get_keys()`). Because NOX does not provide a language-level `private` keyword, `KeyRingState` computes a cryptographic SHA-256 integrity seal (`_integrity_hash`) over `(version, created_at, canonical _keys state)` at construction and verifies it in constant time (`nox.crypto.constant_time_eq`) inside `verify_integrity()`, `get_keys()`, and `key_count()`. Any direct external mutation of `state.version`, `state.created_at`, or `state._keys` fails closed with `ConfigurationError`.
2. **Pre-commit Validation:** The incoming key's `trust_domain`, state, and uniqueness of `kid` are validated on cloned snapshots before any state transition.
3. **Seqlock Coherent Snapshot Publication & Exception-Safe Lock Release (`_commit_state` & `_read_consistent_state`):**
   - State commits acquire a hardware-backed writer lock (`_write_lock: nox.atomic.AtomicBool` via `nox_atomic_cas`) inside a `try ... except Exception:` block that unconditionally releases `_write_lock.store(False)` on any error path and rolls back state/version/sequence if `cas_won == True`.
   - Writers advance the hardware version cell (`_atomic_version.compare_and_swap(base_ver, base_ver + 1)`), enter an odd Seqlock sequence (`_seq.store(base_ver * 2 + 1)`), publish `self._state = new_state` FIRST, and finally seal the commit with an even Seqlock sequence (`_seq.store((base_ver + 1) * 2)`).
   - Readers (`get_version()`, `get_state()`, `get_snapshot()`, `get_signing_key()`, `get_verification_key()`) all read through `_read_consistent_state()`, verifying an even sequence number before and after capturing `self._state` (`s1 == s2 and st.version * 2 == s1`) plus `st.verify_integrity()`. Readers never observe a new version number paired with a stale key snapshot.

### Decoupled IP Syntax Parsing, SSRF Policy & Negative Cache Boundaries
`jwks.nox` strictly separates syntactic IP parsing from SSRF security policy evaluation:
- **Syntactic Layer (`parse_ipv4` -> `IPv4Address`, `parse_ipv6` -> `IPv6Address`):** Enforces exact 4-octet decimal IPv4 syntax (rejecting octal leading zeros, hex, and out-of-range octets) and RFC 4291 8-hextet IPv6 expansion (correctly accounting for embedded 32-bit IPv4 suffixes such as `::ffff:8.8.8.8` as two 16-bit hextets, and rejecting multiple `::`, zone IDs `%`, or malformed segments with `EncodingError`).
- **SSRF Policy Layer (`is_restricted_ipv4_addr`, `is_restricted_ipv6_addr`):** Evaluates validated address structures against all 14 non-routable IPv4 CIDR blocks (`0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10` CGNAT, `127.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`, `192.0.0.0/24`, `192.0.2.0/24`, `192.88.99.0/24`, `192.168.0.0/16`, `198.18.0.0/15` Benchmark, `198.51.100.0/24`, `203.0.113.0/24`, `224.0.0.0/4+`) and IPv6 special/transition ranges (Loopback `::1`, Unspecified `::`, IPv4-mapped `::ffff:0:0/96`, IPv4-compatible, NAT64 `64:ff9b::/96`, 6to4 `2002::/16`, Teredo `2001::/23`, ULA `fc00::/7`, Link-Local `fe80::/10`, Site-Local `fec0::/10`, Multicast `ff00::/8`, Discard `100::/64`, Documentation `2001:db8::/32` & `3fff::/20`).
- **Post-Resolution Verification (`verify_resolved_ip`):** Requires syntactic validity first (`parse_ipv4` / `parse_ipv6`), returning `false` on any malformed IP string before evaluating `!is_restricted_ipv4_addr` / `!is_restricted_ipv6_addr`.


- Rejects all RFC 1918 private IPv4 ranges (`10.0.0.0/8`, `192.168.0.0/16`, and all 16 subnets of `172.16.0.0/12`).
- Negative cache is bounded by `MAX_NEGATIVE_CACHE_ENTRIES` (256) with FIFO eviction, preventing memory exhaustion attacks under random `kid` floods.
- Note on transport: Full socket pinning and DNS rebinding protections belong to NOX's common HTTP transport layer when remote HTTP fetching is integrated.
